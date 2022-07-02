# Perm2c-Algebra Abstracta

**Integrantes:**

*   Gabriel Ivan Rodriguez Postigo
*   Jaime Mateo Gutiérrez Muñoz
*   Alexander Carpio Mamani

**Como correr el codigo:**
* Para poder ver y probar el trabajo selecione el archivo "Perm_2c.ipynb" y luego clickear en "Open in colab" para poder correr el programa.



**RSA KEY GENERATOR
```python
class RSA:
  def __init__(self, k, info=False):

    n = 1
    while True:
      self.e, self.d, self.n = self.RSA_KEY_GENERATOR(k, 10**n)
      m = random.randint(2,self.n-1)
      c = self.Cifrado(m)
      if m == self.Descifrado(c):
        break
      else:
        n += 1

    if info:
      print("RSA (s={:}, e={:}, d={:}, n={:}, phi={:})".format(10**n, self.e, self.d, self.n, self.phi))

  def RSA_KEY_GENERATOR(self, k, s):
    if k<8:    # generar primos con bits menores al dividirlos entre 2 no abria muchos, ocurria un loop, o un error.
      k = 8
    p = RANDOMGEN_PRIMOS(k//2, s)
    q = RANDOMGEN_PRIMOS(k//2, s)
    while p==q:
      q = RANDOMGEN_PRIMOS(k//2, s)

    n, self.phi = p*q, (p-1)*(q-1)

    e = random.randint(2,n-1)
    while Euclides(e, self.phi)!=1:
      e = random.randint(2, n-1)
      
    d = Inversa(e, self.phi)
    return e, d, n

  def Cifrado(self, m):
    return EXPMOD(m, self.e, self.n)

  def Descifrado(self, c):
    return EXPMOD(c, self.d, self.n)
  
  def Cifrado_msg(self, msg):
    cade = ""
    data = []
    for m in msg:
      me = self.Cifrado(ord(m))    # pasamos el valor en ascci de la palabra a el Cifrado RSA
      encrip = me % ord('A') + 65   # rango [65, 122] donde 65='A' y 122='z'
      cade += str("%c" % encrip)   # convertimos de decimal a word ascci
      data.append(me)
    return cade, data

  def Descifrado_msg(self, msg, data):
    cade = ""
    for i in range(len(msg)):
      med = self.Descifrado(data[i])
      cade += str("%c" % med)
    return cade

  def get_edn(self):
    return self.e, self.d, self.n

rsa = RSA(59, True)   # definir k = n bits

mensaje = 13
print("\nMensaje original: ", mensaje)
c = rsa.Cifrado(mensaje)
print("Cifrado: ", c)
print("Descifrado: ", rsa.Descifrado(c))

e,d,n = rsa.get_edn()

print("\ne*d mod phi =", e*d % rsa.phi)    # e*d mod n = 1 mod n
print("phi | (e*d - 1) = ", (e*d-1) % rsa.phi)   # phi | (e*d - 1)
print("mgd(e, phi)={:}\t mgd(d,phi)={:}".format(Euclides(e, rsa.phi), Euclides(d, rsa.phi)))
```
**output:**
```
RSA (s=10000, e=16385075402760093, d=93236124964774545, n=103366470122510461, phi=103366469478339772)

Mensaje original:  13
Cifrado:  84648693784905735
Descifrado:  13

e*d mod phi = 1
phi | (e*d - 1) =  0
mgd(e, phi)=1	 mgd(d,phi)=1
```

**3. (8 points) Validar firmas digitales: Verificar que P(S(m)) = HASH(M) para 3 mensajes distintos, mostrando la respectiva firma σ en cada caso. Utilice la Función Hash SHA-1 para generar m a través de un texto M ( por ejemplo Hola Mundo). Utilizar b = 32 bits en el algoritmo RSA.

```python
import hashlib
h = hashlib.sha1()
rsa = RSA(32)   # definimos los 32 bits

print(" m\t\t\t|\t c = S(m)\t\t|\t Hash(m)\t\t\t|\t m = P(S(m))")
print("-"*125)

words = ["Hola Mundo", "Juego de Monos", "pichanga fiufiu"]
for word in words:
  rsa_word, data = rsa.Cifrado_msg(word)

  h.update(bytes(word, encoding="utf-8"))
  hash_word = h.hexdigest()
  
  rsa_word_2 = rsa.Descifrado_msg(rsa_word, data)

  print(word + " "*(25-len(word)) + rsa_word + " "*(32-len(rsa_word)) + hash_word + " "*10 + rsa_word_2)
```
**output:**

```
 m			|	 c = S(m)		|	 Hash(m)			|	 m = P(S(m))
-----------------------------------------------------------------------------------------------------------------------------
Hola Mundo               ZfxPnkehf                      48124d6dc3b2e693a207667c32ac672414913994          Hola Mundo
Juego de Monos           ukc^fPhcPnfefe                  5a6a086036594daa479a73504459d3e140b2d39f          Juego de Monos
pichanga fiufiu          hENBxe^xPpEkpEk                 62fe33ab9565eb96cd1da8109c0eebcef6e060a1          pichanga fiufiu
```
