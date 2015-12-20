DROP DATABASE IF EXISTS speedmao;
CREATE DATABASE speedmao DEFAULT character SET utf8;
use speedmao;

DROP TABLE IF EXISTS `account`;
CREATE TABLE `account` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `username` varchar(64) NOT NULL,
  `password` varchar(64) NOT NULL,
  `order_id` int(10) unsigned NOT NULL,
  `money` decimal(12,2) NOT NULL,
  `transfer` bigint(20) unsigned NOT NULL,
  `change_traffic` int(10) unsigned NOT NULL DEFAULT 10,
  `log_enable` tinyint(4) NOT NULL,
  `disable` tinyint(4) NOT NULL,
  `login_time` datetime NOT NULL,
  `addtime` datetime NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

DROP TABLE IF EXISTS `order_list`;
CREATE TABLE `order_list` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `account_id` int(10) unsigned NOT NULL,
  `server` varchar(255) NOT NULL,
  `transfer` bigint(20) unsigned NOT NULL,
  `relay_server` varchar(255) NOT NULL,
  `traffic_limit` int(10) unsigned NOT NULL,
  `relay_traffic_limit` int(10) unsigned NOT NULL,
  `over_limit_price` decimal(12,2) NOT NULL,
  `relay_over_limit_price` decimal(12,2) NOT NULL,
  `starttime` datetime NOT NULL,
  `endtime` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

DROP TABLE IF EXISTS `server_list`;
CREATE TABLE `server_list` (
  `server` varchar(255) NOT NULL,
  `price` decimal(12,2) NOT NULL,
  `traffic_limit` int(10) unsigned NOT NULL,
  `over_limit_price` decimal(12,2) NOT NULL,
  `detail` varchar(255) NOT NULL,
  `disable` tinyint(4) NOT NULL,
  `addtime` datetime NOT NULL,
  PRIMARY KEY (`server`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

DROP TABLE IF EXISTS `relay_server_list`;
CREATE TABLE `relay_server_list` (
  `relay_server` varchar(255) NOT NULL,
  `relay_price` decimal(12,2) NOT NULL,
  `traffic_limit` int(10) unsigned NOT NULL,
  `over_limit_price` decimal(12,2) NOT NULL,
  `detail` varchar(255) NOT NULL,
  `disable` tinyint(4) NOT NULL,
  `addtime` datetime NOT NULL,
  PRIMARY KEY (`relay_server`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
