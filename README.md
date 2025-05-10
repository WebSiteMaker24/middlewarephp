# PRSECURE - Projet de Sécurisation PHP

## Description

**PRSECURE** est un projet PHP visant à sécuriser les applications web avec des pratiques modernes de gestion de session, de cookies et de nettoyage des données d'entrée. Ce projet inclut un middleware qui assure la sécurité de l'application à différents niveaux :

- Démarrage sécurisé de la session
- Protection contre les attaques XSS via un nettoyage des entrées utilisateur
- Protection contre le vol de session et de cookies
- Validation des données de session

## Fonctionnalités

### 1. **Session sécurisée**
   La classe `Middleware` permet de garantir que les sessions sont toujours sécurisées, avec des configurations telles que la protection contre les attaques de fixation de session, la vérification de l'IP et de l'User-Agent, ainsi que la régénération de l'ID de session pour éviter les vols de session.

### 2. **Sécurisation des entrées**
   Le middleware applique une méthode de nettoyage des données d'entrée pour éviter les attaques de type XSS (Cross-Site Scripting), en filtrant les données entrantes via `$_GET`, `$_POST`, `$_COOKIE`, et `$_SESSION`.

### 3. **Protection contre le vol de cookies**
   La classe `Middleware` assure également une protection contre le vol de cookies en utilisant des cookies sécurisés, avec des paramètres comme `SameSite`, `Secure` et `HttpOnly` pour éviter toute exploitation malveillante.

### 4. **Sanitization des variables globales**
   La méthode `sanitizeGlobals()` applique une sanitation des variables globales pour éviter toute tentative d'injection de données dangereuses.

## Installation

1. Clonez ce projet dans votre environnement de développement local :

   ```bash
   git clone https://github.com/username/PRSECURE.git
   cd PRSECURE
