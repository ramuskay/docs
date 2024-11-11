Sur test-kubmaster
#A suivre
#https://stackoverflow.com/questions/59155154/how-to-set-cgroup-driver-for-kubelet-in-centos7-2
kubeadm init --apiserver-advertise-address=10.201.203.173 --node-name=$HOSTNAME --pod-network-cidr=10.244.0.0/16
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
echo "source <(kubectl completion bash)"



## Notes

kubectl run myshell -it  --image busybox -- sh --> Demarre un pod nommé myshell avec l'image busybox 
kubectl delete pods myshell --> Delete le pod myshell
kubectl delete deploy myshell --> Supprime le déploiement myshell (et donc le pod en théorie à confirmer)
kubectl create deployment monnginx --image nginx --> Créé un déploiement de type nginx
kubectl describe deploy monnginx --> equivalent docker inspect mais pour un déploiement
kubectl describe pods monnginx --> Très pratique !!
kubectl create service nodeport monnginx --tcp=8080:80 --> Map un port (ici 8080) vers le port 80 via la methode nodeport
kubectl scale deploy monnginx --replicas=2 --> Permet de scaler horizontalement (ici 2 pods). Peux augment ou downsize !
kubectl autoscale deployment monnginx --min 1 --max 5 --> Autoscale automatiquement
kubectl get componentstatuses --> Avoir le statut des composant master
kubectl get daemonsets.apps -n kube-system --> Tous les pods qui fonctionnent en arrière plan
kubectl get all --> Liste tout exhaustivement
kubectl get events --> Permet d'avoir un historique des evenement sur le cluster
kubectl explain pods --> man kubectl
kubectl get pods --selector "env=dev" --show-labels --> Get pods avec un selector (sur les labels)
kubectl apply -f nginx.yml --> Applique la ressource depuis un fichier

## Délaratif

```yml
apiVersion: v1 #API kubernetes 
kind: Pod #La ressource voulue
metadata: #les notes sur la ressource
  name: monpod
  namespace: aurel
  labels:
    env: prod
    prio: 5
spec: #Squelette de la ressource, ils partagent les mêmes port et IP
  containers:
  - name: nginx
    image: nginx
    ports:
    - containerPort: 80
  - name: mondebian
    image: debian
    command: ["tail", "-f"]
```


Sur test-kubnode
