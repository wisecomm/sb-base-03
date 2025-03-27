create table tb_user
(
    user_sq serial
        constraint tb_user_pk
            primary key,
    user_id text,
    user_pw text,
    user_nm text,
    user_st text
);

alter table tb_user
    owner to localmaster;


CREATE TABLE `tb_user` (
  `uid` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '일련번호',
  `user_id` varchar(255) NOT NULL COMMENT '사용자ID',
  `user_pw` varchar(255) DEFAULT NULL COMMENT '사용자비밀번호',
  `user_nm` varchar(255) NOT NULL COMMENT '이름',
  `user_st` text DEFAULT NULL COMMENT '설명',
  PRIMARY KEY (`uid`),
  KEY `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
    