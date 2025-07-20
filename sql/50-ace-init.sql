USE `ace`;
INSERT INTO company ( id, name ) VALUES ( 1, 'default' );
INSERT INTO tags ( id, name ) VALUES ( 1, 'whitelisted' );
INSERT INTO users ( id, username, password_hash, email, omniscience, timezone, display_name )
VALUES ( 1, 'ace', NULL, 'ace@localhost', 0, NULL, 'automation');
INSERT INTO users ( id, username, password_hash, email, omniscience, timezone, display_name )
VALUES ( 2, 'analyst', 'pbkdf2:sha256:150000$MeWyGorw$433cf8984d385cec417cc5081140d3ee3edba8263cd49eb979209c6fabcd56bf', 'analyst@localhost', 0, 'Etc/UTC', 'analyst');
INSERT INTO `settings` (`key`, `type`) VALUES ('root', 'Dictionary');
INSERT INTO `event_status` (`value`) VALUES ('OPEN'), ('INTERNAL COLLECTION'), ('CLOSED'), ('IGNORE');
INSERT INTO `event_remediation` (`value`) VALUES ('not remediated'), ('cleaned with antivirus'), ('cleaned manually'), ('reimaged'), ('credentials reset'), ('removed from mailbox'), ('network block'), ('domain takedown'), ('NA'), ('escalated');
INSERT INTO `event_vector` (`value`) VALUES ('corporate email'), ('webmail'), ('usb'), ('website'), ('unknown'), ('business application'), ('compromised website'), ('sms');
INSERT INTO `event_risk_level` (`value`) VALUES ('1'), ('2'), ('3'), ('0');
INSERT INTO `event_prevention_tool` (`value`) VALUES ('response team'), ('ips'), ('fw'), ('proxy'), ('antivirus'), ('email filter'), ('application whitelisting'), ('user'), ('edr');
INSERT INTO `event_type` (`value`) VALUES ('phish'), ('recon'), ('host compromise'), ('credential compromise'), ('web browsing'), ('pentest'), ('third party'), ('large number of customer records'), ('public media');
COMMIT;

USE `ace-unittest`;
INSERT INTO company ( id, name ) VALUES ( 1, 'default' );
COMMIT;

USE `ace-unittest-2`;
INSERT INTO company ( id, name ) VALUES ( 1, 'default' );
COMMIT;