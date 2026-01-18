The PKI infrastructure as 3 levels:
root_ca trust level
org_ca intermediate level signed by root_ca
doctors leaf level signed by org_ca

- For creating certificate root_ca, make sure to have Openssl and in your terminal run:
Go to ./root_ca


openssl genrsa -out "name_of_your_root_certificate".key 4096
openssl req -x509 -new -nodes -key "name_of_your_root_certificate".key -sha256 -days 3650 \
  -subj "/CN=HealthRootCA" \
  -out "name_of_your_root_certificate".crt


- For creating certificate org_ca, make sure to have Openssl and in your terminal run:

Go to ./org_ca

openssl genrsa -out "name_of_your_org_certificate".key 4096
openssl req -new -key "name_of_your_org_certificate".key \
 -subj "/O="name_of_your_org"/CN="name_of_your_org" CA" \
  -out "name_of_your_org_certificate".csr

openssl x509 -req -in "name_of_your_org_certificate".csr \
  -CA path/"name_of_your_root_certificate".crt -CAkey path/"name_of_your_root_certificate".key -CAcreateserial \
  -out "name_of_your_org_certificate".crt -days 1825 -sha256

- For creating certificate doctor leaf level, make sure to have Openssl and in your terminal run:
Go to ./doctors
openssl genrsa -out "name_of_your_doctor_certificate".key 2048
openssl req -new -key "name_of_your_doctor_certificate".key \
  -subj "/CN="name_of_your_doctor"/O="name_of_your_org"" \
  -out "name_of_your_doctor_certificate".csr

openssl x509 -req -in "name_of_your_doctor_certificate".csr \
  -CA path/"name_of_your_org_certificate".crt -CAkey path/"name_of_your_org_certificate".key -CAcreateserial \
  -out "name_of_your_doctor_certificate".crt -days 365 -sha256


In frontend, when the doctor is signing up, he has to provide certificate coming from ./doctors

