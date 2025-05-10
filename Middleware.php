<?php

class Middleware {
    public static function middleware() {
        self::activeSession();
        self::antiVolSession();
        self::sanitizeGlobals();
    }
    // Nettoie les données d'entrée pour éviter les injections XSS, etc.
    public static function sanitize($data) {
        if (is_array($data)) {
            return array_map([self::class, 'sanitize'], $data);
        }
        return htmlspecialchars(strip_tags(trim($data)), ENT_QUOTES, 'UTF-8');
    }

    // Méthode à appeler au démarrage pour tout nettoyer
    public static function sanitizeGlobals() {
        $_GET     = self::sanitize($_GET);
        $_POST    = self::sanitize($_POST);
        $_COOKIE  = self::sanitize($_COOKIE);

        if (session_status() === PHP_SESSION_ACTIVE) {
            $_SESSION = self::sanitize($_SESSION);
        }
    }
        // Démarrage de la session
        public static function activeSession() {
            if (session_status() == PHP_SESSION_NONE) {
                // 1. Options de sécurité pour la session
                ini_set('session.use_strict_mode', 1);
                ini_set('session.cookie_httponly', 1);
                ini_set('session.cookie_secure', isset($_SERVER['HTTPS'])); // true seulement en HTTPS
                ini_set('session.use_only_cookies', 1);
                session_start(); // Démarre la session
            }
        }
        // Configuration du cookie (nom, durée, chemin, etc.)
        public static function activeCookie() {
        session_name('SESSION_ID'); // Personnalise le nom du cookie
        session_set_cookie_params([
            'lifetime' => 0,              // Session expire à la fermeture du navigateur
            'path' => '/',
            'domain' => '',               // Par défaut, domaine courant
            'secure' => isset($_SERVER['HTTPS']), // Uniquement en HTTPS
            'httponly' => true,           // JS ne peut pas lire le cookie
            'samesite' => 'Strict'        // Strict : empêche l'envoi inter-domaines (CSRF)
        ]);
        }
        // Regénération de l'ID de session pour éviter le vol de session
        public static function antiVolSession($force = false) {
            $sessionTimeout = 3600; // 60 minutes d'inactivité
            $userIP = $_SERVER['REMOTE_ADDR'];
            $userAgent = $_SERVER['HTTP_USER_AGENT'];
        
            // Vérifie si l'utilisateur est toujours actif
            if (isset($_SESSION['initiated']) && (time() - $_SESSION['initiated'] > $sessionTimeout)) {
                session_destroy(); // Invalide la session après une période d'inactivité
                session_start(); // Redémarre une nouvelle session
            }
        
            if (!isset($_SESSION['initiated']) || $force) {
                session_regenerate_id(true); // Renouvelle l'ID de session
                $_SESSION['initiated'] = time(); // Marque le démarrage de la session
        
                // Sauvegarder l'IP et l'User-Agent dans la session
                $_SESSION['user_ip'] = $userIP;
                $_SESSION['user_agent'] = $userAgent;
            } else {
                // Vérifie que l'IP et l'User-Agent correspondent à la session précédente
                if ($_SESSION['user_ip'] !== $userIP || $_SESSION['user_agent'] !== $userAgent) {
                    session_destroy(); // Invalide la session si l'IP ou l'User-Agent ne correspond pas
                    session_start(); // Redémarre une nouvelle session
                    // Optionnellement, afficher un message d'erreur ou rediriger l'utilisateur
                }
            }
        }
        
        // Anti vol de cookie : vérifie l'existence du cookie et le régénère si nécessaire
        public static function antiVolCookie($force = false) {
            // Vérifie si le cookie "SESSION_ID" existe ou si on force la réinitialisation
            if (!isset($_COOKIE['SESSION_ID']) || $force) {
                // Renouvelle le cookie avec les options de sécurité renforcées
                $cookieParams = [
                    'lifetime' => 0, // La session expire à la fermeture du navigateur
                    'path' => '/',   // Le cookie est valable pour tout le domaine
                    'domain' => '',   // Par défaut, le domaine actuel
                    'secure' => isset($_SERVER['HTTPS']), // Le cookie ne sera transmis que sur une connexion HTTPS
                    'httponly' => true, // Le cookie ne peut pas être accédé par JavaScript
                    'samesite' => 'Strict' // Empêche l'envoi du cookie lors de requêtes inter-domaines
                ];
                
                // Définit un cookie de session sécurisé
                setcookie('SESSION_ID', session_id(), time() + 3600, '/', '', $cookieParams['secure'], $cookieParams['httponly']);
                
                // Regénère l'ID de session pour éviter les attaques de fixation
                session_regenerate_id(true);
            }
        
            // Stocke un indicateur "initié" dans $_COOKIE pour éviter une réinitialisation à chaque requête
            if (!isset($_COOKIE['initiated']) || $force) {
                $_COOKIE['initiated'] = time();
            }
        }
}