SunX509 chat encription example
==================================
Generate server keystore
keytool -selfcert -genkey -keyalg RSA -sigalg SHA1withDSA -alias tomcat -keystore server.jks -storepass changeit -validity 360 -keysize 2048 -dname "cn=pappzdev.integrity.hu, ou=Development team, o=Integrity Ltd., c=HU"

Export server public x.509 certificate
keytool -keystore server.jks -export -alias tomcat -file tomcat.cer

Generate client keystore
keytool -selfcert -genkey -keyalg DSA -sigalg SHA1withDSA -alias pzoli -keystore client.jks -storepass changeit -validity 360 -keysize 2048 -dname "cn=Papp Zoltan, ou=Development team, o=Integrity Ltd., c=HU"

Export client public x.509 certificate
keytool -keystore client.jks -export -alias pzoli -file pzoli.cer

Import both public and client public keys to trusted keystore
(an ask about password for trusted.jks will appear before trusted.jks generate)
keytool -importcert -keystore trusted.jks -alias tomcat -file tomcat.cer
keytool -importcert -keystore trusted.jks -alias pzoli -file pzoli.cer

List keys in keystore
keytool -list -keystore trusted.jks
====================================
