# AES
With this library you can use power of AES to encrypt anything from simple text to huge files easily.

##Usage
Here we encrypt and decrypt a simple text include a RAR archive.

```java
var aes = new AES(AES.generateKey(AES.AES_KEY_256), AES.generateIv());
var filePath = "file.rar";

Files.write(Path.of(filePath), aes.encryptFile(new File(filePath)));
Files.write(Path.of(filePath), aes.decryptFile(new File(filePath)));

String text = "This is a sample text", enc = null, dec = null;

enc = aes.encrypt(text);
dec = aes.decrypt(enc);

System.out.println(text);
System.out.println(enc);
System.out.println(dec);
System.out.println(dec.equals(text));
---
