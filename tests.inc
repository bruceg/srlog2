sender=${tmp}/sender
receiver=${tmp}/receiver

KEYDIR=${tmp}
PORT=62144
SENDER=sender
SERVER=localhost
export KEYDIR PORT SENDER SERVER

cd ${tmp}

echo curve25519:6JH+h0pNEr7k9RoGCB+02RgGwtubhYkm1URwH0l0DWs= >curve25519
echo curve25519:TM7oIdoyfCO/n1Bsfj7+0wLULx33yhk0zEk3qRtUAEw= >curve25519.pub
echo nistp224:KlptWkgo8OVsRtvyJ/Y6hPsQpVoZUu7fby0+Qw== >nistp224
echo nistp224:kpthtYt+4wnPGGUkWNhzQo56QFY0PzDDdmv3Kw== >nistp224.pub

mkdir servers
echo curve25519:H466d963DtBcdtMZ6iN/A6WGu1vDbWuprp0s+khygCM= >servers/localhost.curve25519
echo nistp224:h7OoQ5jDDBW1wNZFss9AClWlOrMcZ1x+rxOrdg== >servers/localhost.nistp224

cleanup() {
  cd ${tmp}
  rm -rf receiver sender
}

setup() {
  cleanup

  mkdir receiver
  cd receiver
  echo sender:curve25519:TM7oIdoyfCO/n1Bsfj7+0wLULx33yhk0zEk3qRtUAEw= >senders
  echo sender:nistp224:kpthtYt+4wnPGGUkWNhzQo56QFY0PzDDdmv3Kw== >>senders
  echo curve25519:IC59FBExpUFvJB2ZeCEKB1nuYWt+DRyyxj/l5u2d00w= >secrets
  echo nistp224:aFXlMf5xs4f3kSAhKzfYLcXp6X6yAfqFJL9iLw== >>secrets
  chmod 444 senders
  cd ..

  mkdir sender
  cd sender
  echo 0:0 >sequence
  cd ..
}

startit() {
  setup
  cd ${tmp}/receiver
  ${src}/srlog2d -p $PORT >log 2>/dev/null &
  pid=$!
  cd ${tmp}/sender
}

stopit() {
  kill $pid
  sed -e 's/^@40000000................ //' \
  	${receiver}/log
  cleanup
  cd ${tmp}
}
