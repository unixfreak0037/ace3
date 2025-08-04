-- MySQL dump 10.13  Distrib 5.7.29, for Linux (x86_64)
--
-- Host: localhost    Database: email-archive
-- ------------------------------------------------------
-- Server version	5.7.29-0ubuntu0.18.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

CREATE DATABASE IF NOT EXISTS `email-archive`;
ALTER DATABASE `email-archive` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci;
USE `email-archive`;

--
-- Table structure for table `archive`
--

DROP TABLE IF EXISTS `archive`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `archive` (
  `archive_id` int(11) NOT NULL AUTO_INCREMENT,
  `server_id` int(11) NOT NULL,
  `hash` binary(32) NOT NULL,
  `insert_date` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`archive_id`, `insert_date`),
  UNIQUE KEY `idx_server_id` (`server_id`,`hash`, `insert_date`),
  KEY `idx_insert_date` (`insert_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
PARTITION BY RANGE COLUMNS(insert_date) (
  PARTITION p_catchall VALUES LESS THAN (MAXVALUE)
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `archive_index`
--

DROP TABLE IF EXISTS `archive_index`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `archive_index` (
  `field` enum('env_from','env_to','body_from','body_to','subject','decoded_subject','message_id','content','url') NOT NULL,
  `hash` binary(32) NOT NULL,
  `archive_id` int(11) NOT NULL,
  `insert_date` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`hash`,`archive_id`,`field`, `insert_date`),
  KEY `idx_archive_id` (`archive_id`),
  KEY `idx_field_hash` (`field`,`hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
PARTITION BY RANGE COLUMNS(insert_date) (
  PARTITION p_catchall VALUES LESS THAN (MAXVALUE)
);

/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `email_history`
--

DROP TABLE IF EXISTS `email_history`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `email_history` (
  `id` BIGINT NOT NULL AUTO_INCREMENT,
  `insert_date` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `message_id` TEXT NOT NULL,
  `message_id_hash` BINARY(32) NOT NULL,
  `recipient` TEXT NOT NULL,
  `recipient_hash` BINARY(32) NOT NULL,
  PRIMARY KEY (`id`, `insert_date`),
  KEY `idx_eh_insert_date` (`insert_date`),
  KEY `idx_eh_message_id` (`message_id_hash`),
  KEY `idx_eh_recipient` (`recipient_hash`),
  UNIQUE KEY `idx_eh_message_id_recipient` ( `message_id_hash`, `recipient_hash`, `insert_date` )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
PARTITION BY RANGE COLUMNS(insert_date) (
  PARTITION p_catchall VALUES LESS THAN (MAXVALUE)
);

/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `archive_server`
--

DROP TABLE IF EXISTS `archive_server`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `archive_server` (
  `server_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostname` varchar(256) NOT NULL,
  PRIMARY KEY (`server_id`),
  UNIQUE KEY `idx_hostname` (`hostname`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2020-01-28 13:58:16
