## Concept

Ordonnenceur / Scheduleur  
Run de jobs  
Pipeline CI : build/run/test  

### Jobs

Plusieurs type de job :
- Freestyle: simple standard (pour du script par ex)
- Pipeline
- Tache externe


### Trigger + remote launch

Comment le job va etre lance si ce n'est pas manuel

Trigger : 
- Sur echec
- Sur reussite
- Dans tout les cas

On peut trigger :
- via hook URL (remote URL)
- via build d'un autre projet (selon son statut)
- via cron (correspond a la syntaxe cron)
- via Git trigger

### Parametres

On peut indiquer plusieurs parametres : 

- Mot de passe 
- string
- bool
- choix via liste
- parametres d'execution
- identifiants (gestion des secrets)
- fichiers
- texte

Ces parametres peuvent etre utilise dans le build (ex: parametre mdp, echo $mdp)  
Parametres d'execution permet de recup les parametres d'autres build  

## Pipeline

Chaine d'action / jobs decrits par du code en Groovy

Ex : 
```
pipeline {
    agent any 
    stages {
        stage('Build') { 
            steps {
                // 
            }
        }
        stage('Test') { 
            steps {
                // 
            }
        }
        stage('Deploy') { 
            steps {
                // 
            }
        }
    }
}
```

Decrit via des JenkinsFile qui a pour avantage : 
- Declaratif
- Versionnable
- Portatif sans modif

## Docker et Jenkins


Utilite :
- Run des container et travailler dedans
- Run des containers pour faire des tests dessus
- Build des images pour les livrer en prod

Si on simplifie, deux cas :
- agent : on travaille dans le conteneur (le conteneur est un host)
- node : on travaille de l'exterieur du conteneur (le conteneur est une cible)

## Users & Roles

Possibilite de creer des users et des roles  
Possibilite d'attribuer des roles a des users et de les correler a des jobs (avec des regles d'auto-adhesion) 


## Plugin git

On peut grace au plugin git :
- Git cloner automatiquement grace a des vars
- Lancer un build lors d'un commit 
- Push sur git lors d'un build (si build ok par ex)
- Ajouter une image docker a la registry d'un projet Gitlab

## Custom

Vue :

- objectif : organiser le classement des jobs
- soit une vue personnalisee
- soit des vues de classement
- permet de filtrer les files de lanceurs et de constructions
- peut etre alimenee par une regex de filtre (Java_ ...)

