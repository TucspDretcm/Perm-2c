# Perm2c-Algebra Abstracta

**Integrantes:**

*   Gabriel Ivan Rodriguez Postigo
*   Jaime Mateo Gutiérrez Muñoz
*   Alexander Carpio Mamani

**Como correr el codigo:**
* Para poder ver y probar el trabajo selecione el archivo "Perm_2c.ipynb" y luego clickear en "Open in colab" para poder correr el programa.


<h3>RSA KEY GENERATOR</h3>

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

<h3>3. (8 points) Validar firmas digitales: Verificar que P(S(m)) = HASH(M) para 3 mensajes distintos, mostrando la respectiva firma σ en cada caso. Utilice la Función Hash SHA-1 para generar m a través de un texto M ( por ejemplo Hola Mundo). Utilizar b = 32 bits en el algoritmo RSA.</h3>

```python
import hashlib
rsa = RSA(32)   # definimos los 32 bits

print(" M\t\t\t|\t m\t\t|\t Hash(m)\t\t\t|\t m = S(m)\t|\t m = P(S(m))")
print("-"*125)

words = ["Hola Mundo", "Juego de Monos", "pichanga fiufiu"]
for word in words:
  H = hashlib.sha1(bytes(word, encoding="utf-8")).hexdigest()
  m = int(H, 16) % rsa.n
  word_S = rsa.Descifrado(m)
  word_P = rsa.Cifrado(word_S)
  print(word + " "*(25-len(word)) + str(m) + " "*(22-len(str(m))) + H + " "*5 + str(word_S) + " "*(22-len(str(word_S))) + str(word_P))
```

**output:**

```
 M			|	 m		|	 Hash(m)			|	 m = S(m)	|	 m = P(S(m))
-----------------------------------------------------------------------------------------------------------------------------
Hola Mundo               548693899             48124d6dc3b2e693a207667c32ac672414913994     982569751             548693899
Juego de Monos           1438384090            d665ddfb6fe9d2c61d287468e375b2fd92a47f15     463421013             1438384090
pichanga fiufiu          1528502847            3d81f39719f5f26c5aeba7b19f57ffe062557c1e     625484321             1528502847
```


<h3>Punto adicional para el Examen Final: Utilizar el algoritmo RSA (b = 32) para generar y validar una firma digital. Utilizar el estándar PKCS 1 v1.5 para añadir un padding al mensaje original. Fecha límite de entrega: 08/07/22.</h3>

```python
import hashlib, sys

def gen_EB(M, bits):
  H = hashlib.sha1(bytes(M, encoding="utf-8")).hexdigest()
  PS = "F" * (bits - sys.getsizeof(H) - 3)
  T = hex(RANDOMGEN_PRIMOS(bits, 100))[2:] + H
  return "0001" + PS + "00" + T


def StringToInt(EB):
  return int(EB, base=16)


def IntToString(c):
  return hex(c)[2:]


bits = 32
rsa = RSA(bits)

EB = gen_EB("Hola mundo", bits)
m = StringToInt(EB)
c = rsa.Descifrado(m)  # m^d mod n
OB = IntToString(c)

print("\"m\" original: ", m % rsa.n)    # "m" original aplicando modulo para normalizar tanto la original como la "m" recuperada
print("Firma digital:", OB)
print("\"m\" recuperada: ", rsa.Cifrado(c))
```

**output:**

```
"m" original:  1481651286
Firma digital: 76cda0f1
"m" recuperada:  1481651286
```
