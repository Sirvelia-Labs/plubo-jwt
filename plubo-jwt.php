<?php

/**
 * @wordpress-plugin
 * Plugin Name:       PLUBO JWT
 * Plugin URI:        https://sirvelia.com/
 * Description:       Create, verify and manage your JWTs easily..
 * Version:           1.0.0
 * Author:            Albert Tarrés - Sirvelia
 * Author URI:        https://sirvelia.com/
 * License:           GPL-3.0+
 * License URI:       http://www.gnu.org/licenses/gpl-3.0.txt
 * Text Domain:       plubo-jwt
 * Domain Path:       /languages
 */

define( 'PLUBO_JWT_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
require_once PLUBO_JWT_PLUGIN_DIR . 'vendor/autoload.php';