# faceitverifbot
Warface Faceit Hub verification system originally developed for WFC

# Infrastructure
- Python-flask published through apache reverse proxy externally
- It uses MariaDB as database but you can just change the ORM and potentially run on whatever you want
- The CSID (game account ID) is being retrieved by using my own WFStats API
- Runs in a PM2 ecosystem

The admin dashboard to manage users won't be released alongside this verification backend.

# Verification logic
1. User enters his in-game name in the home
2. Checking if user is online through WFStats playerInfo API
3. CSID is returned and is being checked if the user is already registered
4. If user is not registered then redirect to Discord Oauth2 to get the discord ID
5. If Discord ID is not already registered then redirect to Faceit Oauth2 to get the faceit ID
6. If Faceit ID is not already registered then register ingame name, csid, discord id, faceit id and current timestamp

# Config
The repo has a `config.template.json` file, just set the values for your project and then rename into `config.json`. You will need to create a Discord Bot with oauth2 capabilities and configure the scopes accordingly. The same for Faceit, you need the API keys and an account with admin permissions in the hubs with which you can give roles with its API bearer token.<br>
You also need the RSA keys for the JWT token verification to avoid tampering. Just run `certs/rotatekeys.sh`

# Database
Create the database with the name you want (as long as you configure it accordingly into the config file) and then create the table schema like the following:

```SQL
CREATE TABLE `users` (
  `id` int(6) unsigned NOT NULL AUTO_INCREMENT,
  `game` varchar(30) NOT NULL,
  `csid` varchar(100) DEFAULT NULL,
  `discord` varchar(50) NOT NULL,
  `faceit_name` varchar(50) DEFAULT NULL,
  `faceit` varchar(100) NOT NULL,
  `reg_date` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
```
