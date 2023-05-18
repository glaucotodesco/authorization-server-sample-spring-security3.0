INSERT INTO TBL_USER (name, email, password) VALUES ('Admin User', 'adm','$2a$10$eACCYoNOHEqXve8aIWT8Nu3PkMXWBaOxJ9aORUYzfMQCbVBIhZ8tG');
INSERT INTO TBL_USER (name, email, password) VALUES ('Operator User', 'user', '$2a$10$eACCYoNOHEqXve8aIWT8Nu3PkMXWBaOxJ9aORUYzfMQCbVBIhZ8tG');

INSERT INTO TBL_ROLE (role) VALUES ('ROLE_OPERATOR');
INSERT INTO TBL_ROLE (role) VALUES ('ROLE_ADMIN');

INSERT INTO TBL_USER_ROLE (user_id, role_id) VALUES (1, 1);
INSERT INTO TBL_USER_ROLE (user_id, role_id) VALUES (1, 2);
INSERT INTO TBL_USER_ROLE (user_id, role_id) VALUES (2, 1);