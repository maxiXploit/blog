


<h1 style="
    color: #00ff00;
    background: #031200; 
    border-radius: 10px;
    border-radius: 10px; 
    padding: 10px;     
    font-family: 'Courier New';
    text-align: center; 
"> 
 Kerberos y los ataques AS-REP roast y Kerberoasting attack
</h1>


Entender de forma clara este protocolo es esencial como funcionan los ataques más comunes en entornos de Active Directory. Hay muchas explicaciones por internet, algunas no tan detalladas, algunas erroneas, he hecho la página de wikipedia tiene una explicación en español con un par de errores y una explicación no tan extendida, por lo que nos basaremos en esta explicación agregando un esquema de colores para seguir de forma más sencilla el flujo y añadiendo más detalles en cada paso del proceso. 


1. El usuario accede al cliente Kerberos en su equipo con sus credenciales y el cliente manda una AS-REQ al AS, este AS-REQ consiste del ID del cliente en texto plano. 

2. El AS revisa si el ID del cliente está en su base de datos, si está, genera una clave secreta, que no es más que la contraseña hasheada del usuario, contraseña que reside en la base de datos del AS. 
Con este hash cifra 2 mensajes
  Mensaje A: Un Client/TGS session key cifrado con la clave secreta derivada de la contraseña del usuario. 
  Mensaje B: Un Ticket-Granting-Ticket(TGT), este TGT no es más que un "paquete" que contiene <ID del cliente, dirección de red del cliente(ip), el tiempo en el que es válido el ticket, y el Client/TGS session key del mensaje A>, todo esto está cifrado, primero con la llave secreta del TGS, y después con la clave secreta del usuario. 

   ```bash 
    (((TGT)<llave secreta del TGS>)<clave derivada del usuario>)
   ``` 
Estos mensajes son enviados al cliente, si la contraseña proporcionada por el usuario era la correcta, el cliente será capaz de crear la misma clave derivada del usuario que se usó para encriptar los mensajes, permitiendo desencriptar estos mensaje. 
El cliente desencripta el Client/TGS session key(mensaje A), que se usará para las siguiente conexiones con el TGS y descifra parcialmente el TGT

3. Ahora el cliente tiene todo lo necesario para presentarte ante el TGS, así que le envía dos mensajes: 
  Mensaje C: El TGT, que está encriptado con la clave secreta del TGS y el ID del servicio al que se quiere acceder. 
  Mensaje D: Compuesto del ID del cliente y una marca de tiempo, todo esto encriptado con el Client/TGS session key, que se encuentra en el TGT. 

4. Una vez que el TGS recibe los mensajes C y D, será capaz de desencriptar el TGT con su clave secreta para obtener el Client/TGS session key y el ID del usuario, el Client/TGS session key para desencriptar el mensaje C, que también contiene el ID del usuario y la marca de tiempo, compara ambos ID y si todo es correcto manda los siguientes mensajes al usuario. 
  Mensaje E: Client-to-server ticket(que incluye el ID del cliente, la dirección de red del cliente, periodo de validación, y un Client/Server session key) encriptado con el la clave secreta del servicio
  Mensaje F: CLient/Server session key, encriptado con el Client/TGS session key. 

5. El cliente recibe estos dos mensajes, desencripta el Client/Server session key con el Client/TGS session key que ya posee, el Client-to-server ticket no puede desencriptarlo. Con esto ya puede autenticarse ante el servicio y le manda los siguientes mensajes. 
  Mensaje E: el  mensaje E del paso anterior. 
  Mensaje G: Un nuevo autenticador, que se compone con el ID del cliente y una marca de tiempo. 

6. El Servicio desencripta el mensaje E, de este obtiene Client/Server session key, y lo usa para desencripar el mensaje G para confirmar que todo esté bien, y envía un último mensaje al cliente para que el ciente pueda confiar en el servicio. 
  Mensaje H: Una marca de tiempo, que es la misma que se encuentra en el mensaje G, mas 1 segundo(aunque en la versión 5 ya no es necesario). esto encriptado con el Client/Server session key.

7. El usuario desencripta la marca de tiempo, verifica la marca de tiempo y si todo es correcto, el usuario ya puede confiar en el servicio. 

8. El servidor provee el servicio solicitado por el cliente. 





