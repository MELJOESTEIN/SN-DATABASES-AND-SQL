# Rapport Final : Projet SN-DATABASES AND SQL

## Introduction

Ce rapport présente les résultats de l'analyse de la base de données organization dans le cadre du projet SN-DATABASES AND SQL. L'objectif était d'explorer les tentatives de connexion (log_in_attempts) et les informations des employés (employees) pour identifier des comportements suspects et proposer des recommandations de sécurité. Le projet était structuré en six étapes :

1. Reconnaissance : Comprendre la structure de la base de données.
2. Failed Infiltrations : Analyser les tentatives de connexion échouées.
3. After Hours Activity : Examiner les connexions hors heures de travail.
4. Insider Threat : Évaluer les menaces internes dans le département IT.
5. Cross-Reference Investigation : Croiser les données pour détecter des anomalies.
6. Comprehensive Security Audit : Fournir un rapport global et des recommandations.

Les résultats, bien que limités par un jeu de données restreint, révèlent des anomalies significatives exploitables pour renforcer la sécurité de l'organisation.

## Méthodologie

### Environnement

- Système : Linux (MySQL).
- Base de données : organization.
- Outils : MySQL pour les requêtes, Bash pour l'exportation des résultats.

### Données

- **Table log_in_attempts** : Contient les tentatives de connexion.
  - Colonnes : event_id, username, login_date, login_time, country, ip_address, success.

- **Table employees** : Contient les informations des employés.
  - Colonnes : employee_id, device_id, username, department, office.

### Processus

- Importation du fichier database.sql dans la base organization :
  ```bash
  mysql -u root -p organization < /home/muhammad/Downloads/SN-DATABASES-AND-SQL/database.sql
  ```

- Exécution de requêtes SQL pour chaque étape.
- Exportation des résultats dans /home/muhammad/SN-DATABASES-AND-SQL/results.txt :
  ```bash
  mysql organization -e "SELECT ..." >> /home/muhammad/SN-DATABASES-AND-SQL/results.txt
  ```

### Limitation

- Le jeu de données est restreint : 5 tentatives de connexion (3 échecs, 2 succès) et 1 employé IT.
- Cela limite les analyses approfondies, comme l'identification de patterns complexes ou de menaces internes récurrentes.

## Résultats par Étape

### Étape 1 : Reconnaissance

**Objectif** : Identifier les tables et leurs colonnes.

**Requêtes** :
```sql
SHOW TABLES;
DESCRIBE log_in_attempts;
DESCRIBE employees;
```

**Résultats** :

- Tables : employees, log_in_attempts.
- Colonnes de log_in_attempts :

| Field | Type | Null | Key | Default | Extra |
|-------|------|------|-----|---------|-------|
| event_id | int | NO | PRI | NULL | auto_increment |
| username | varchar(50) | NO | | NULL | |
| login_date | date | NO | | NULL | |
| login_time | time | NO | | NULL | |
| country | varchar(50) | NO | | NULL | |
| ip_address | varchar(15) | NO | | NULL | |
| success | tinyint(1) | NO | | NULL | |

- Colonnes de employees :

| Field | Type | Null | Key | Default | Extra |
|-------|------|------|-----|---------|-------|
| employee_id | int | NO | PRI | NULL | auto_increment |
| device_id | varchar(50) | NO | | NULL | |
| username | varchar(50) | NO | | NULL | |
| department | varchar(50) | NO | | NULL | |
| office | varchar(50) | NO | | NULL | |

**Analyse** :

- Deux tables avec des colonnes permettant d'analyser les connexions et de relier les utilisateurs aux départements via username.
- Structure bien adaptée pour les analyses de sécurité.

### Étape 2 : Failed Infiltrations

**Objectif** : Analyser les tentatives de connexion échouées.

**Requêtes** :
```sql
SELECT COUNT(*) AS failed_attempts
FROM log_in_attempts
WHERE success = FALSE;

SELECT username, COUNT(*) AS failed_count
FROM log_in_attempts
WHERE success = FALSE
GROUP BY username
HAVING failed_count > 1
ORDER BY failed_count DESC;

SELECT HOUR(login_time) AS hour, country, COUNT(*) AS failed_count
FROM log_in_attempts
WHERE success = FALSE
GROUP BY HOUR(login_time), country
ORDER BY failed_count DESC;
```

**Résultats** :

- Nombre d'échecs : 3.
- Utilisateurs avec plusieurs échecs : Empty set.
- Patterns horaires/pays :

| hour | country | failed_count |
|------|---------|--------------|
| 19 | MEX | 1 |
| 20 | CAN | 1 |
| 22 | UK | 1 |

**Analyse** :

- 3 tentatives échouées par ajonson, mjohnson, sbrown, chacune à une heure différente (19h, 20h, 22h) et dans un pays différent (MEX, CAN, UK).
- Aucun utilisateur n'a plusieurs échecs, et aucun pattern clair ne se dégage en raison du faible volume de données.

### Étape 3 : After Hours Activity

**Objectif** : Analyser les connexions hors heures (avant 9h ou après 17h).

**Requêtes** :
```sql
SELECT COUNT(*) AS after_hours_attempts
FROM log_in_attempts
WHERE HOUR(login_time) < 9 OR HOUR(login_time) > 17;

SELECT success, COUNT(*) AS attempt_count
FROM log_in_attempts
WHERE HOUR(login_time) < 9 OR HOUR(login_time) > 17
GROUP BY success;

SELECT username, COUNT(*) AS after_hours_count
FROM log_in_attempts
WHERE HOUR(login_time) < 9 OR HOUR(login_time) > 17
GROUP BY username
HAVING after_hours_count > 1
ORDER BY after_hours_count DESC;
```

**Résultats** :

- Nombre de tentatives hors heures : 4.
- Réussies vs échouées :

| success | attempt_count |
|---------|---------------|
| 0 | 3 |
| 1 | 1 |

- Employés fréquents hors heures : Empty set.

**Analyse** :

- 4 tentatives hors heures : 3 échecs (19h15, 20h30, 22h15) et 1 succès (17h30).
- Les échecs dominent, et aucun utilisateur n'a plusieurs tentatives hors heures, limitant l'identification de comportements réguliers.

### Étape 4 : Insider Threat

**Objectif** : Évaluer les menaces internes dans le département IT.

**Requêtes** :
```sql
SELECT COUNT(*) AS it_employees
FROM employees
WHERE department = 'IT';

SELECT office, COUNT(*) AS employee_count
FROM employees
WHERE department = 'IT'
GROUP BY office;

SELECT username, COUNT(DISTINCT device_id) AS device_count
FROM employees
WHERE department = 'IT'
GROUP BY username
HAVING device_count > 1;
```

**Résultats** :

- Nombre d'employés IT : 1.
- Bureaux :

| office | employee_count |
|--------|---------------|
| South-045 | 1 |

- Anomalies device_id : Empty set.

**Analyse** :

- Un seul employé IT dans South-045, sans anomalie de device_id.
- Aucun lien avec les tentatives échouées, réduisant le risque de menace interne dans IT.

### Étape 5 : Cross-Reference Investigation

**Objectif** : Croiser les données pour identifier des comportements suspects.

**Requêtes** :
```sql
SELECT e.department, COUNT(*) AS failed_count
FROM log_in_attempts l
JOIN employees e ON l.username = e.username
WHERE l.success = FALSE
GROUP BY e.department
ORDER BY failed_count DESC
LIMIT 1;

SELECT l.country, COUNT(*) AS failed_count
FROM log_in_attempts l
LEFT JOIN employees e ON l.username = e.username
WHERE l.success = FALSE
AND l.country NOT IN (SELECT office FROM employees)
GROUP BY l.country;

SELECT e.department, HOUR(l.login_time) AS hour, COUNT(*) AS attempt_count
FROM log_in_attempts l
JOIN employees e ON l.username = e.username
WHERE l.success = FALSE
GROUP BY e.department, HOUR(l.login_time)
ORDER BY attempt_count DESC;
```

**Résultats** :

- Département avec le plus d'échecs :

| department | failed_count |
|------------|--------------|
| Sales | 1 |

- Pays non-bureaux :

| country | failed_count |
|---------|--------------|
| MEX | 1 |
| CAN | 1 |
| UK | 1 |

- Patterns départements/horaires :

| department | hour | attempt_count |
|------------|------|---------------|
| Sales | 19 | 1 |
| Finance | 20 | 1 |
| HR | 22 | 1 |

**Analyse** :

- Les échecs sont répartis entre Sales, Finance, HR, sans domination claire.
- MEX, CAN, UK ne sont pas des bureaux, confirmant leur caractère suspect.
- Les échecs hors heures (19h, 20h, 22h) suggèrent des attaques externes.

### Étape 6 : Comprehensive Security Audit

**Objectif** : Fournir un rapport global et des recommandations.

**Requêtes** :
```sql
SELECT 
    l.username,
    e.department,
    e.office,
    l.login_date,
    l.login_time,
    l.success,
    l.country,
    l.ip_address,
    e.device_id
FROM log_in_attempts l
JOIN employees e ON l.username = e.username
ORDER BY l.login_date, l.login_time;

SELECT 
    e.department,
    e.office,
    SUM(CASE WHEN l.success = TRUE THEN 1 ELSE 0 END) AS success_count,
    SUM(CASE WHEN l.success = FALSE THEN 1 ELSE 0 END) AS failed_count,
    ROUND(SUM(CASE WHEN l.success = TRUE THEN 1 ELSE 0 END) / COUNT(*), 2) AS success_rate
FROM log_in_attempts l
JOIN employees e ON l.username = e.username
GROUP BY e.department, e.office;

SELECT DISTINCT office
FROM employees;
```

**Résultats** :

- Rapport global :

| username | department | office | login_date | login_time | success | country | ip_address | device_id |
|----------|------------|--------|------------|------------|---------|---------|------------|-----------|
| jsmith | Marketing | East-170 | 2022-05-08 | 17:30:00 | 1 | USA | 192.168.1.1 | D001 |
| ajonson | Sales | North-110 | 2022-05-09 | 19:15:00 | 0 | MEX | 192.168.1.2 | D002 |
| mjohnson | Finance | West-223 | 2022-05-09 | 20:30:00 | 0 | CAN | 192.168.1.3 | D003 |
| jdoe | IT | South-045 | 2022-05-10 | 08:45:00 | 1 | USA | 192.168.1.4 | D004 |
| sbrown | HR | East-180 | 2022-05-10 | 22:15:00 | 0 | UK | 192.168.1.5 | D005 |

- Corrélations :

| department | office | success_count | failed_count | success_rate |
|------------|--------|---------------|--------------|--------------|
| Marketing | East-170 | 1 | 0 | 1.00 |
| Sales | North-110 | 0 | 1 | 0.00 |
| Finance | West-223 | 0 | 1 | 0.00 |
| IT | South-045 | 1 | 0 | 1.00 |
| HR | East-180 | 0 | 1 | 0.00 |

- Bureaux :

| office |
|--------|
| East-170 |
| North-110 |
| West-223 |
| South-045 |
| East-180 |

**Analyse** :

- 5 tentatives : 3 échecs (MEX, CAN, UK) et 2 succès (USA).
- Les échecs sont hors heures (19h15, 20h30, 22h15) et depuis des pays non-bureaux, indiquant des attaques externes probables.
- Les succès (Marketing à 17h30, IT à 8h45) semblent légitimes, mais la connexion à 17h30 est juste hors heures.
- Aucun employé IT impliqué dans les échecs.

## Analyse Globale

### Anomalies Détectées

1. **Tentatives échouées suspectes** :
   - 3 échecs depuis MEX, CAN, UK, qui ne sont pas des bureaux (East-170, North-110, West-223, South-045, East-180).
   - Toutes hors heures (19h15, 20h30, 22h15), renforçant leur caractère suspect.

2. **Connexions hors heures** :
   - 4 des 5 tentatives sont hors heures (3 échecs, 1 succès à 17h30).

3. **Ciblage des départements** :
   - Les échecs ciblent Sales, Finance, HR, mais pas IT ni Marketing.

4. **Absence de menace interne dans IT** :
   - Un seul employé IT, sans échecs ni anomalies de device_id.

### Limites

- **Faible volume de données** : 5 tentatives (3 échecs, 2 succès) et 1 employé IT limitent les patterns et analyses complexes.
- **Manque de contexte** : Les bureaux ne sont pas géographiquement liés à des pays (par exemple, South-045 vs USA), compliquant l'interprétation.
- **Données statiques** : Pas de logs supplémentaires pour détecter des tendances à long terme.

## Recommandations de Sécurité

1. **Liste blanche géographique** :
   - Bloquer les connexions depuis des pays non-bureaux (MEX, CAN, UK) via un pare-feu :
     ```bash
     iptables -A INPUT -s 192.168.1.2 -j DROP  # Exemple pour MEX
     ```
   - Utiliser un WAF (par exemple, ModSecurity) pour une protection avancée.

2. **Surveillance hors heures** :
   - Configurer des alertes dans un SIEM (ELK Stack, Splunk) pour les connexions avant 9h ou après 17h :
     ```bash
     mysql organization -e "SELECT * FROM log_in_attempts WHERE HOUR(login_time) < 9 OR HOUR(login_time) > 17;" > /home/muhammad/SN-DATABASES-AND-SQL/after_hours.log
     ```

3. **Authentification multifacteur (MFA)** :
   - Activer MFA pour tous les utilisateurs, en priorité pour Sales, Finance, HR :
     - Outils : Google Authenticator, Duo Security.
     - Exemple : Intégration avec PAM sur Linux.

4. **Audit des appareils** :
   - Vérifier que chaque utilisateur a un seul device_id. Bien que aucune anomalie n'ait été détectée, maintenir cette pratique.

5. **Formation des employés** :
   - Sensibiliser aux attaques par force brute et aux connexions depuis des emplacements inhabituels.
   - Organiser des sessions trimestrielles.

6. **Amélioration des données** :
   - Collecter plus de logs pour des analyses futures.
   - Ajouter des colonnes comme user_agent ou session_duration dans log_in_attempts.

## Synthèse

L'analyse a identifié trois tentatives de connexion échouées suspectes depuis MEX, CAN, et UK, toutes hors heures, ciblant Sales, Finance, et HR. Ces tentatives, provenant de pays non-bureaux, suggèrent des attaques externes. Les départements Marketing et IT n'ont pas d'échecs, et aucun risque interne n'a été détecté dans IT. Les recommandations (liste blanche, MFA, surveillance) visent à prévenir de futures attaques. Malgré un jeu de données limité, les résultats fournissent des insights exploitables pour sécuriser l'organisation.

## Conclusion

Ce projet a permis de :

- Maîtriser les requêtes SQL pour l'analyse de logs.
- Résoudre des problèmes techniques (importation, exportation).
- Identifier des anomalies et proposer des solutions de cybersécurité.

Les compétences acquises sont applicables à des audits de sécurité réels. Un jeu de données plus large permettrait des analyses plus approfondies à l'avenir. Le rapport et les recommandations sont prêts à être soumis pour évaluation.


