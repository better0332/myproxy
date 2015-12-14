DROP DATABASE IF EXISTS speedmao_log;
CREATE DATABASE speedmao_log DEFAULT character SET utf8;
use speedmao_log;

DROP TABLE IF EXISTS `tcp_log`;
CREATE TABLE `tcp_log` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `username` varchar(64) NOT NULL,
  `proxy_type` varchar(16) NOT NULL,
  `client_addr` varchar(32) NOT NULL,
  `remote_addr` varchar(255) NOT NULL,
  `transfer` bigint(20) unsigned NOT NULL,
  `starttime` datetime NOT NULL,
  `endtime` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

DROP TABLE IF EXISTS `udp_log`;
CREATE TABLE `udp_log` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `tid` int(10) unsigned NOT NULL,
  `remote_addr` varchar(32) NOT NULL,
  `transfer` bigint(20) unsigned NOT NULL,
  `addtime` datetime NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `tid_remote_addr` (`tid`,`remote_addr`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
