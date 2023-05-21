# Setting the test environment

## A. Install Apache and PHP

To set up an Apache PHP server in Linux Ubuntu, you can follow these steps:

1. Update the package repository:
   ```
   sudo apt update
   ```

2. Install Apache web server:
   ```
   sudo apt install apache2
   ```

3. Start the Apache service:
   ```
   sudo systemctl start apache2
   ```

4. Enable Apache to start on boot:
   ```
   sudo systemctl enable apache2
   ```

5. Install PHP and required modules:
   ```
   sudo apt install php libapache2-mod-php php-mysql
   ```

6. Configure Apache to use PHP module:
   ```
   sudo nano /etc/apache2/mods-enabled/dir.conf
   ```

   Inside the file, you should see a line that looks like this:
   ```
   DirectoryIndex index.html index.cgi index.pl index.php index.xhtml index.htm
   ```

   Move the `index.php` option to the beginning, so it looks like this:
   ```
   DirectoryIndex index.php index.html index.cgi index.pl index.xhtml index.htm
   ```

   Save the file and exit the text editor.

7. Restart the Apache service for the changes to take effect:
   ```
   sudo systemctl restart apache2
   ```

8. Test PHP:
   Create a PHP test file named `info.php` in the default web directory:
   ```
   sudo nano /var/www/html/info.php
   ```

   Add the following code to the file:
   ```php
   <?php
   phpinfo();
   ?>
   ```

   Save the file and exit the text editor.

9. Open a web browser and visit `http://localhost/info.php`. You should see the PHP information page displaying various details about your PHP installation.

Once you have completed these steps, your Apache PHP server should be set up and ready to use on your Linux Ubuntu system.

## B. Website Setup

1. Configure Apache:
   - Open the Apache configuration file using a text editor:
     ```
     sudo nano /etc/apache2/sites-available/test.com.conf
     ```
    Paste the following configuration into the file:
     ```
     <VirtualHost *:80>
         ServerName test.com
         DocumentRoot /path/to/Test_web
         <Directory /path/to/Test_web>
             Options Indexes FollowSymLinks MultiViews
             AllowOverride All
             Require local
         </Directory>
     </VirtualHost>
     ```
   - Save the file and exit the text editor.

3. Enable the site and restart Apache:
   - Enable the site:
     ```
     sudo a2ensite test.com.conf
     ```
   - Restart Apache for the changes to take effect:
     ```
     sudo service apache2 restart
     ```

4. Update hosts file (optional):
   - Open the hosts file:
     ```
     sudo nano /etc/hosts
     ```
   - Add the following line at the end of the file to map your domain name to the localhost IP (`127.0.0.1`):
     ```
     127.0.0.1   test.com
     ```
   - Save the file and exit the text editor.

You can access it by typing `http://test.com` in your browser's address bar.


4. Permission Error Resolution (optional)
    Incase you get error as 

    ```
    Forbidden
    You don't have permission to access this resource.
    Apache/2.4.52 (Ubuntu) Server at test.com Port 80
    ```

    Give recurive permission as follows:
    ```
    sudo chmod +x /path/
    sudo chmod +x /path/to/
    sudo chmod +x /path/to/Test_web
    ```


