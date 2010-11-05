sender=${tmp}/sender
receiver=${tmp}/receiver

KEYDIR=${tmp}
PORT=62144
SENDER=sender
SERVER=localhost
export KEYDIR PORT SENDER SERVER

cd ${tmp}

cleanup() {
  cd ${tmp}
  rm -f nistp224* curve25519*
  rm -rf receiver sender servers
}

setup_nistp224_keys() {
  echo nistp224:KlptWkgo8OVsRtvyJ/Y6hPsQpVoZUu7fby0+Qw== >nistp224
  echo nistp224:kpthtYt+4wnPGGUkWNhzQo56QFY0PzDDdmv3Kw== >nistp224.pub
  echo sender:nistp224:kpthtYt+4wnPGGUkWNhzQo56QFY0PzDDdmv3Kw== >>receiver/senders
  echo nistp224:aFXlMf5xs4f3kSAhKzfYLcXp6X6yAfqFJL9iLw== >>receiver/secrets
  echo nistp224:h7OoQ5jDDBW1wNZFss9AClWlOrMcZ1x+rxOrdg== >servers/localhost.nistp224
}

setup_curve25519_keys() {
  echo curve25519:6JH+h0pNEr7k9RoGCB+02RgGwtubhYkm1URwH0l0DWs= >curve25519
  echo curve25519:TM7oIdoyfCO/n1Bsfj7+0wLULx33yhk0zEk3qRtUAEw= >curve25519.pub
  echo sender:curve25519:TM7oIdoyfCO/n1Bsfj7+0wLULx33yhk0zEk3qRtUAEw= >>receiver/senders
  echo curve25519:IC59FBExpUFvJB2ZeCEKB1nuYWt+DRyyxj/l5u2d00w= >>receiver/secrets
  echo curve25519:H466d963DtBcdtMZ6iN/A6WGu1vDbWuprp0s+khygCM= >servers/localhost.curve25519
}

setup_all_keys() {
  setup_curve25519_keys
  setup_nistp224_keys
}

setup() {
  cleanup

  mkdir receiver servers
  setup_${1:-all}_keys
  chmod 444 receiver/senders

  mkdir sender
  echo 0:0 >sender/sequence
}

startit() {
  setup $1
  cd ${tmp}/receiver
  env UID=`id -u` GID=`id -g` \
  ${src}/srlog2d -p $PORT -U >log 2>errlog &
  pid=$!
  cd ${tmp}/sender
}

stopit() {
  cat sequence
  kill $pid
  sed -e 's/^@40000000................ //' \
  	${receiver}/log
  cleanup
  cd ${tmp}
}
