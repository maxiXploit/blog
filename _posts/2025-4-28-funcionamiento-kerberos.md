


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

---

<div style="
    background: #0b3f00; 

1. El usuario accede al cliente Kerberos en su equipo con sus credenciales y el cliente manda una AS-REQ al AS, este AS-REQ consiste del ID del cliente en texto plano. 

2. El AS revisa si el ID del cliente está en su base de datos, si está, genera una clave secreta, que no es más que la contraseña hasheada del usuario, contraseña que reside en la base de datos del AS. 
Con este hash cifra 2 mensajes
  Mensaje A: Un Client/TGS session key cifrado con la clave secreta derivada de la contraseña del usuario. 
  Mensaje B: Un Ticket-Granting-Ticket(TGT), este TGT no es más que un "paquete" que contiene <ID del cliente, dirección de red del cliente(ip), el tiempo en el que es válido el ticket, y el Client/TGS session key del mensaje A>, todo esto está cifrado, primero con la llave secreta del TGS, y después con la clave secreta del usuario. 

   ```bash 
    {{{TGT}<llave secreta del TGS>}<clave derivada del usuario>}
   ``` 
Estos mensajes son enviados al cliente, si la contraseña proporcionada por el usuario era la correcta, el cliente será capaz de crear la misma clave derivada del usuario que se usó para encriptar los mensajes, permitiendo desencriptar èstos mismos.

3. Si

">

Hola

</div>
    

