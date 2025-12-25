/************************************************************************************
* Set the credit card number in Purchase to encrypted credit card numbers
*************************************************************************************/

SET SQL_SAFE_UPDATES = 0;

USE marketplace;

UPDATE Purchase SET CreditCardNumber = 'fGd10a46VT4C99RTtDJZqG0XRa8/oPElDBUcMh3+Qs4qFHS59+DU1CgLS1dqGZZ61+Yp';

SET SQL_SAFE_UPDATES = 1;