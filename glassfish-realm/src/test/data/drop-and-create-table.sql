USE jdbcrealmdb;
DROP TABLE IF EXISTS `jdbcrealmdb`.`groups`;
DROP TABLE IF EXISTS `jdbcrealmdb`.`users`;

CREATE TABLE `jdbcrealmdb`.`users` (`username` varchar(255) NOT NULL,`salt` varchar(255) NOT NULL,`password` varchar(255) DEFAULT NULL,PRIMARY KEY (`username`)) ENGINE=InnoDB DEFAULT CHARSET=utf8;
CREATE TABLE `jdbcrealmdb`.`groups` (`username` varchar(255) DEFAULT NULL,`groupname` varchar(255) DEFAULT NULL)ENGINE=InnoDB DEFAULT CHARSET=utf8;
CREATE INDEX groups_users_FK1 ON groups(username ASC);

