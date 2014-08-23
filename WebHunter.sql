/*
Navicat MySQL Data Transfer

Source Server         : 10.1.17.152
Source Server Version : 50169
Source Host           : 10.1.17.152:3306
Source Database       : WebHunter

Target Server Type    : MYSQL
Target Server Version : 50169
File Encoding         : 65001

Date: 2013-11-26 13:50:59
*/

SET FOREIGN_KEY_CHECKS=0;

-- ----------------------------
-- Table structure for info
-- ----------------------------
DROP TABLE IF EXISTS `info`;
CREATE TABLE `info` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `scheme` varchar(16) NOT NULL,
  `method` varchar(16) NOT NULL,
  `host` varchar(256) NOT NULL,
  `domain` varchar(256) NOT NULL,
  `path` varchar(1024) NOT NULL,
  `status` char(3) NOT NULL,
  `reqConLen` int(11) NOT NULL,
  `respConLen` int(11) NOT NULL,
  `post` varbinary(10240) NOT NULL,
  `fileinfo` varbinary(1024) NOT NULL,
  `req` mediumblob NOT NULL,
  `count` int(11) unsigned NOT NULL,
  `time` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `host` (`host`),
  KEY `time` (`time`),
  KEY `domain` (`domain`)
) ENGINE=MyISAM AUTO_INCREMENT=0 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Table structure for vul
-- ----------------------------
DROP TABLE IF EXISTS `vul`;
CREATE TABLE `vul` (
  `id` int(11) unsigned NOT NULL,
  `vultype` int(11) NOT NULL,
  `sig` varchar(128) NOT NULL,
  `req` mediumblob NOT NULL,
  `resp` mediumblob NOT NULL,
  `checktime` datetime NOT NULL,
  KEY `id` (`id`),
  KEY `vultype` (`vultype`),
  KEY `checktime` (`checktime`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
