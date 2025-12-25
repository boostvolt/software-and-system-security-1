/************************************************************************************
* Create the database named marketplace, all of its tables, and the marketplace user
* Modified for Docker - uses '%' instead of 'localhost' for user host
*************************************************************************************/

-- Create marketplace database

DROP DATABASE IF EXISTS marketplace;

CREATE DATABASE marketplace;

-- Create tables and set content

USE marketplace;

CREATE TABLE User (
    Username VARCHAR(20) NOT NULL,
    PasswordHash VARCHAR(100) NOT NULL,
    Role VARCHAR(20) NOT NULL,

    PRIMARY KEY (Username)
);

INSERT INTO User VALUES ('alice', '$2a$12$ykZiPR6HpMQn4zmglfmCdepHvAkcTuym/vs5ct72aivVFna2pVTMG', 'SALES'),
						('bob', '$2a$12$z3oi72rfRkvvXBSsQWsHNOomjOdlitTEEAgbVRJB7BRdkYMyyWGcq', 'BURGERMAN'),
						('daisy', '$2a$12$AyHXCfnuQ6WocKsAZqLqR.RhglXauSkLmck5KbsDIlkNk5jhTK8.u', 'PRODUCTMANAGER'),
						('john', '$2a$12$/kPrxb44vBua5z3LcWVVteExToHZ.3St/V73wjMlmQL/AWu8fNuxC', 'SALES'),
						('luke', '$2a$12$DU4cfWWkwSeKe.BDW.E1KubB5VGffasAvjIniOwk91dLZnuHF0wJm', 'PRODUCTMANAGER'),
						('robin', '$2a$12$IpFfJyZLd.2ip1QDIr2AS./yy0sk490bTV/7bhVD4SbmrvEsU89SW', 'MARKETING'),
						('snoopy', '$2a$12$S6sH70kQe/UtidkDy344VeQKehanQuE7B5bskS2j1Ypvx6gZ97NeW', 'MARKETING');

CREATE TABLE Product (
    ProductID INT NOT NULL AUTO_INCREMENT,
    Description VARCHAR(100) NOT NULL DEFAULT '',
    Price DECIMAL(9,2) NOT NULL DEFAULT '0.00',
    Username VARCHAR(15) NOT NULL,

    PRIMARY KEY (ProductID),
    FOREIGN KEY (Username) REFERENCES User(Username)
);

INSERT INTO Product VALUES
  (1, 'DVD Life of Brian - used, some scratches but still works', 5.95, 'daisy'),
  (2, 'Ferrari F50 - red, 43000 km, no accidents', 250000.00, 'luke'),
  (3, 'Commodore C64 - used, the best computer ever built', 444.95, 'luke'),
  (4, 'Printed Software-Security script - brand new', 10.95, 'daisy');

CREATE TABLE Purchase (
    PurchaseID INT NOT NULL AUTO_INCREMENT,
    Firstname VARCHAR(50) NOT NULL DEFAULT '',
    Lastname VARCHAR(50) NOT NULL DEFAULT '',
    CreditCardNumber VARCHAR(100) NOT NULL DEFAULT '',
    TotalPrice DECIMAL(10,2) NOT NULL DEFAULT '0.00',

    PRIMARY KEY (PurchaseID)
);

INSERT INTO Purchase VALUES (1, 'Ferrari', 'Driver', '1111 2222 3333 4444', 250000.00),
                            (2, 'C64', 'Freak', '1234 5678 9012 3456', 444.95),
                            (3, 'Script', 'Lover', '5555 6666 7777 8888', 10.95);

-- Create marketplace user and set rights (using '%' for Docker connectivity)

DROP USER IF EXISTS 'marketplace'@'%';

CREATE USER 'marketplace'@'%' IDENTIFIED BY 'marketplace';

GRANT SELECT         ON `marketplace`.* TO 'marketplace'@'%';
GRANT UPDATE         ON `marketplace`.`User` TO 'marketplace'@'%';
GRANT INSERT, DELETE ON `marketplace`.`Product` TO 'marketplace'@'%';
GRANT INSERT, DELETE ON `marketplace`.`Purchase` TO 'marketplace'@'%';

FLUSH PRIVILEGES;
