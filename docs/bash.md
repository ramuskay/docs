$$ : The PID of the program
$! : The PID of the last background job
$? : Return code
$\* : All of the positional parameters, seen as a single word
$@ : Same as $\*, but each parameter is a quoted string, that is, the parameters are passed on intact, without interpretation or expansion
$# : Number of command-line arguments


Utilisation de nohup en **ssh** : 

nohup COMMAND >./nohup.out 2>./nohup.err &
