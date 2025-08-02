-- Update password hashes with correct bcrypt hashes
UPDATE users SET hashed_password = '$2b$12$eKx57mNumfZ5bcFVjOpetOIoP8Kc1quLpu.iginSkhERcivw.6KQK' WHERE email = 'admin@cybershield.com';
UPDATE users SET hashed_password = '$2b$12$tnizbTHT4I7v4D5oQzKxKuIvBWFe8vGIX5aMF5ibt.EZawLpNdbAy' WHERE email = 'analyst@cybershield.com';
UPDATE users SET hashed_password = '$2b$12$dtwCEf6IrDhF/sMOdX1RDeqEw25QwBPGrZ463nJ4bvlzXlJvumDr2' WHERE email = 'user@cybershield.com';
UPDATE users SET hashed_password = '$2b$12$aoXrtvi6Hzb3vPaOX79I.OJ1YoPV6I40J2of8cL6.jatdEPWMNw2O' WHERE email = 'demo@cybershield.com'; 