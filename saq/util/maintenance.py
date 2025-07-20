# vim: sw=4:ts=4:et
import datetime
import os.path
import logging
import shutil

from typing import Optional

from ace_api import upload
from saq.configuration import get_config_value, get_config_value_as_int
from saq.constants import CONFIG_API, CONFIG_API_KEY, CONFIG_GLOBAL, CONFIG_GLOBAL_DISTRIBUTE_DAYS_OLD, CONFIG_GLOBAL_DISTRIBUTION_TARGET, CONFIG_GLOBAL_FP_DAYS, CONFIG_GLOBAL_IGNORE_DAYS, DISPOSITION_FALSE_POSITIVE, DISPOSITION_IGNORE, G_SAQ_NODE
from saq.database import Alert, get_db, retry_sql_on_deadlock
from saq.database.pool import get_db_connection
from saq.environment import g, get_base_dir
from saq.error import report_exception

from sqlalchemy.sql.expression import select, delete

def cleanup_alerts(fp_days_old: Optional[int]=None, ignore_days_old: Optional[int]=None, dry_run: Optional[bool]=False, distribute_days_old: Optional[int]=None):
    """Cleans up the alerts stored in the ACE system. 
       Alerts dispositioned as FALSE_POSITIVE are archived (see :method:`saq.database.Alert.archive`)
       Alerts dispositioned as IGNORE as deleted.
       This is intended to be called from an external maintenance script.

       :param int fp_days_old: By default the age of the alerts to be considered for cleanup
       is stored in the configuration file. Setting this overrides these settings.
       :param int ignore_days_old: By default the age of the alerts to be considered for cleanup
       is stored in the configuration file. Setting this overrides these settings.
       :param bool dry_run: Setting this to True will simply print the number of alerts would
       be archived and deleted. Defaults to False.
    """
    assert isinstance(dry_run, bool)

    if ignore_days_old is None:
        ignore_days_old = get_config_value_as_int(CONFIG_GLOBAL, CONFIG_GLOBAL_IGNORE_DAYS)

    if fp_days_old is None:
        fp_days_old = get_config_value_as_int(CONFIG_GLOBAL, CONFIG_GLOBAL_FP_DAYS)

    if distribute_days_old is None:
        distribute_days_old = get_config_value_as_int(CONFIG_GLOBAL, CONFIG_GLOBAL_DISTRIBUTE_DAYS_OLD)

    try:
        cleanup_ignored_alerts(ignore_days_old, dry_run)
    except Exception as e:
        logging.error("error cleaning up ignored alerts: %s", e)
        report_exception()

    try:
        archive_fp_alerts(fp_days_old, dry_run)
    except Exception as e:
        logging.error("error archiving fp alerts: %s", e)
        report_exception()

    try:
        if distribute_days_old > 0:
            distribute_old_alerts(distribute_days_old, dry_run, get_config_value(CONFIG_GLOBAL, CONFIG_GLOBAL_DISTRIBUTION_TARGET))
    except Exception as e:
        logging.error("error distributing old alerts: %s", e)
        report_exception()

def cleanup_ignored_alerts(days: int, dry_run: bool):
    # delete alerts dispositioned as IGNORE and older than N days
    dry_run_count = 0
    for storage_dir, alert_id in get_db().execute(select(Alert.storage_dir, Alert.id)
        .where(Alert.location == g(G_SAQ_NODE))
        .where(Alert.disposition == DISPOSITION_IGNORE)
        .where(Alert.disposition_time < datetime.datetime.now() - datetime.timedelta(days=days))):

        if dry_run:
            dry_run_count += 1
            continue

        # delete the files backing the alert
        try:
            target_path = os.path.join(get_base_dir(), storage_dir)
            logging.info(f"deleting files {target_path}")
            shutil.rmtree(target_path)
        except Exception as e:
            logging.error(f"unable to delete alert storage directory {storage_dir}: {e}")

        # delete the alert from the database
        logging.info(f"deleting database entry {alert_id}")
        retry_sql_on_deadlock(delete(Alert).where(Alert.id == alert_id), commit=True)

    if dry_run:
        logging.info(f"{dry_run_count} ignored alerts would be deleted")

def archive_fp_alerts(days: int, dry_run: bool):
    # archive alerts dispositioned as False Positive older than N days
    dry_run_count = 0
    for alert in get_db().query(Alert).filter(
        Alert.location == g(G_SAQ_NODE),
        Alert.archived == False,
        Alert.disposition == DISPOSITION_FALSE_POSITIVE,
        Alert.disposition_time < datetime.datetime.now() - datetime.timedelta(days=days)):
    
        if dry_run:
            dry_run_count += 1
            continue

        logging.info(f"resetting false positive {alert}")

        try:
            alert.load()
        except Exception as e:
            logging.error(f"unable to load {alert}: {e}")
            continue

        alert.archive()
        alert.sync()
        
    if dry_run:
        logging.info(f"{dry_run_count} fp alerts would be archived")

def distribute_old_alerts(days: int, dry_run: bool, distribution_target: str, max_count: Optional[int]=0) -> int:
    assert isinstance(days, int)
    assert days >= 1
    assert isinstance(distribution_target, str)
    assert distribution_target
    assert isinstance(max_count, int)

    # move old alerts that are not part of an event to other nodes to free up space
    success_count = 0
    failure_count = 0
    alert_index = 0

    with get_db_connection() as db:
        c = db.cursor()
        c.execute("""
        SELECT
            uuid, storage_dir
        FROM
            alerts
        WHERE
            location = %s
            AND insert_date < DATE_SUB(NOW(), INTERVAL %s DAY)
            AND id NOT IN (
                SELECT alert_id FROM event_mapping
            )""", (g(G_SAQ_NODE), days))

        for uuid, storage_dir in c:
            alert_index += 1
            if max_count > 0:
                if alert_index > max_count:
                    logging.warning("stopping at max count %s", max_count)
                    return success_count

            logging.info("uploading alert %s to %s (dry_run = %s)", uuid, distribution_target, dry_run)
            if dry_run:
                success_count += 1
                continue

            if not os.path.exists(storage_dir):
                logging.warning("alert storage_dir %s does not exist", storage_dir)
                failure_count += 1
                continue

            try:
                upload_result = upload(uuid,
                                       storage_dir,
                                       overwrite=True,
                                       sync=False,
                                       move=True,
                                       remote_host=distribution_target,
                                       api_key=get_config_value(CONFIG_API, CONFIG_API_KEY))
                # {'result': True}
                if isinstance(upload_result, dict) and upload_result.get("result", False):
                    logging.info("uploaded %s to %s", uuid, distribution_target)
                    # delete local storage
                    try:
                        shutil.rmtree(storage_dir)
                        logging.info("deleted %s", storage_dir)
                        success_count += 1
                    except Exception as e:
                        failure_count += 1
                        logging.error("unable to remove local storage_dir %s: %s", storage_dir, e)
                        report_exception()
                else:
                    failure_count += 1
                    logging.error("upload for %s returned non-success %s", uuid, upload_result)

            except Exception as e:
                failure_count += 1
                logging.error("unable to upload alert %s: %s", uuid, e)
                report_exception()

    if dry_run:
        logging.info("%s alerts would be distributed to %s", success_count, distribution_target)
    else:
        logging.info("uploaded %s alerts (%s failures)", success_count, failure_count)

    return success_count
