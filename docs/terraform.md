#Teraform

##Concept

* Construire
* Modifier
* Versionner

Explosion avec le cloud, API centree  
Nombreux providers de dispo (cloud, software, reseau, database etc...)   
Action sur l'infra via fichier de conf (HCL) == InfraAsCode  
Stateful vs Ansible qui lui est stateless   
* Gros interet par rapport a Ansible car si container nginx installe puis on decide d'installer apache alors il deploie apache et surtout supprimer nginx (interet du stateful)  
Utilisation : IAC, maintien d'infra, CI/CD, automatisation d'infra  
* Gros interet par rapport

State : 
* Stockage de l'etat de l'infra et sa config  
* state = terraform.tfstate
* tfstate (reel) >> plan (voulu) >> changements/creation

Different etapes :
* refresh
* plan
* apply
* destroy

Fichiers utilises = .tf  
Developpe en GO  
Resource == une brique d'infra (instance, containers, switch etc...)  
Utilisation de l'API des providers !!  

## Expressions

Conditional Expressions documents the **<CONDITION\> ? <TRUE VAL\> : <FALSE VAL\>** expression, which chooses between two values based on a bool condition.  

Ex : 
Ici on définit un password pk si la variable certificates_pk_encryption est définie alors on vérifie si la variable vs_server_url.type est égal à Thycotic si oui on recupère le password Thycotic sinon celui de cyberark (que deux types différents dans la definition des variables). Si certificates_pk_encryption n'est pas défini alors on set à null   
```
pk_password = var.certificates_pk_encryption ? (var.vs_server_url.type == "thycotic" ? data.tss_secret.pk_password[0].value : data.conjur_secret.pk_password[0].value) : ""
```


For Expressions documents expressions like **[for s in var.list : upper(s)]**, which can transform a complex type value into another complex type value.

## Symbol

### The symbol =>

Ici on voit à quoi sert le symbole "=>", il permet d'associer la clé avec la valeur désignée. Ici la clé rules

```
locals {
  groups = {
    example0 = {
      description = "sg description 0"
      rules = [{
        description = "rule description 0",
      },{
        description = "rule description 1",
      }]
    },
    example1 = {
      description = "sg description 1"
      rules = [{
        description = "rule description 0",
      },{
        description = "rule description 1",
      }]
    }
  }
  rules = { for k,v in local.groups : k => v.rules }
}
output "rules" {
  value = local.rules
}

[OUTPUT]

rules = {
  "example0" = [
    {
      "description" = "rule description 0"
    },
    {
      "description" = "rule description 1"
    },
  ] etc...
```



## Resource

Element qui peut etre CRUD (CreateRemoveUpdateDelete) via le provider  
Un objet d'une ressource est unique (un nom) dans un meme module  

Format :

```
resource "resource_type" "resource_nom"{
  arg = "valeur"
}
```

Exemple : 


```
resource "aws_instance" "web"{
  ami = "som-ami-id"
  instance_type = "t2.micro"
}
```

### Data Source 

C'est une resource non modifiable  
```
data "aws_ami" "ubuntu" {
  most_recent = true
  filter {
    name   = "name"
    values = ["myami-*"]
  }
}
```

### Meta arguments


```
resource "ressource_type" "ressource_nom" {
  count = nb #Pour faire de l'iteration sur la resource
  arg = "valeur"
}
```

### ForEach

Pour iterer

```
variable "instances" {
  type = "map"
  default = {
    clef1 = "123"
    clef2 = "456"
    clef3 = "789"
  }
}
resource "aws_instance" "server" {
  for_each = var.instances 
  ami = each.value
  instance_type = "t2.micro"
  tags = {
    Name = each.key
  }
}
```




## Variables

3 type de variables : 

- string
- list
- map
- number
- bool

Deux manieres de declarer une variable : 

```
output "mavariable" {
  value = var.str
}
output "mavariable" {
  value = "${var.str}"
}
```

Exemple : 

String  
```
variable "str" {
  type = string
  default ="127.0.0.1 gitlab.test"
}

resource "null_resource" "node1" {
 provisioner "local-exec" {
  command = "echo '${var.str}' > hosts.txt"
 }
}
```

Map   
```
variable "hosts" {
  default     = {
    "127.0.0.1" = "localhost gitlab.local"
    "192.169.1.168" = "gitlab.test"
    "192.169.1.170" = "prometheus.test"
  }
}
resource "null_resource" "hosts" {
 for_each = var.hosts
 provisioner "local-exec" {
  command = "echo '${each.key} ${each.value}' >> hosts.txt"
 }
}
```

On peut utiliser un trigger aussi qui lorsque sa valeur change déclanche le provisioner

```
resource "aws_instance" "cluster" {
  count = 3
}
resource "null_resource" "cluster" {
  triggers = {
    cluster_instance_ids = join(",", aws_instance.cluster.*.id)
  }
  connection {
    host = element(aws_instance.cluster.*.public_ip, 0)
  }
  provisioner "remote-exec" {
    inline = [
      "bootstrap-cluster.sh ${join(" ", aws_instance.cluster.*.private_ip)}",
    ]
  }
}
```

List  
```
variable "hosts" {
  default     = ["127.0.0.1 localhost","192.168.1.133 gitlab.test"]
}
resource "null_resource" "hosts" {
 count = "${length(var.hosts)}"
 provisioner "local-exec" {
  command = "echo '${element(var.hosts, count.index)}' >> hosts.txt"
 }
}
```

pro

* definitionplusieurs niveaux : environnement > fichier specifie

* ordre des variables
  * 1 - environnement
  * 2 - fichier : terraform.tfvars
  * 3 - fichier json : terraform.tfvars.json
  * 4 - fichier \*.auto.tfvars ou \*.auto.tfvars.json
  * 5 - CLI : -var ou - var-file 


## Modules

Equivalent d'un role Ansible  
Structure d'un module :  
https://www.terraform.io/language/modules/develop/structure

* utilisation d'un module  

```
module "monmodule" {
  source = "./rep_module"
}
```

* principe d'heritage du provider
    * par defaut celui du fichier dans lequel il est appele  
    * prossibilite de reciser le provider


* possiblite d'instancier plusieurs fois un meme module


```
module "instance1" {
  source = "./rep_module"
}
module "instance2" {
  source = "./rep_module"
}
```


Installation d'un module

```
terraform get
terraform init
```

* peut permettre de gerer la gestion de dependance (pour les prerequis)

```
terraform apply -target=module.docker
terraform apply -target=module.postgres
```


## Modules - Docker


On peut creer des containers via le module docker

Exemple de creation du container nginx: 

```
terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "2.16.0"
    }
  }
}

provider "docker" {
  host = "tcp://127.0.0.1:2375"
}

resource "docker_image" "nginx" {
  name = "nginx:latest"
}
resource "docker_container" "nginx" {
  image = docker_image.nginx.latest
  name  = "enginecks"
  ports {
    internal = 80
    external = 80
  }
}
```

Ici ce qui le plus important c'est d'avoir acces a la socket docker distante pour utiliser son API (securiser avec TLS en prod)


## Module - K8s


DATA SOURCES : sources d'informations (rend de l'info et ne cree rien)


* kubernetes_all_namespaces : liste de tous les NS
* kubernetes_config_map : acces aux configmap
* kubernetes_ingress : liste des ingress
* kubernetes_namespace : information sur un namespace
* kubernetes_secret : liste des secrets (configmaps like)
* kubernetes_service_account : compte de service utilise dans les pods
* kubernetes_service : liste des informations sur un service
* kubernetes_storage_class : informations relatives aux classes de stockages (association PV ET PVC)


RESOURCES : creation d'objets


* kubernetes_pod
* kubernetes_deployment 
* kubernetes_stateful_set (persisntance)
* kubernetes_namespace
* kubernetes_replication_controller
* kubernetes_service
* kubernetes_config_map
* kubernetes_secret












## Destroy

Destroy sur kubernetes a des effets tres precis.
C'est l'inverse de apply

On peut choisir grace a target de supprimer une ressource ou un module




