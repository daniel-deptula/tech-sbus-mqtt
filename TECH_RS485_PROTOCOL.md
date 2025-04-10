# Tech sbus protocol over RS485

## Frame format

The data sent over a serial bus consists of ASCII characters.

A single frame starts with a '>' (0x3E) and ends with a line feed (0x0A). Between these two characters there're two base64-encoded strings:
1) everything without the last 6 characters: **the message**
2) the last 6 characters (without "==" padding): **CRC-32 of the message**

The structure of the message:

| Length (bytes) | Function  |
| ----------- | ----------- |
| 4 | Source address (every regulator or controller has it's own 4-byte address)    |
| 2 | ? (when measurements are sent it's 50 00; in some other messages it's E9 FD)  |
| 4 | Destination address                                                           |
| 2 | ? (looks like it's always the same as the two bytes after the source address) |
| n | The data                                                                      |

## The data
### Temperature and humidity values
One or multiple parameters can be included in one message. In messages sent from the sensor to the controller three bytes mean the type of the parameter and are followed by two bytes with the value.
Types of parameters:
* 04 00 00 - room temperature
* 04 01 00 - floor temperature?
* 04 02 00 - humidity

The values are two-byte integers which divided by 10 give temperature in Celsius degrees or humidity percentage.

Example:
```
04 00 00 f2 00 04 01 00 04 01 04 02 00 4c 02
^^^^^^^^ ^^^^^ ^^^^^^^^ ^^^^^ ^^^^^^^^ ^^^^^
room     24,2  floor    26    humidity 58,8%
temp     deg   temp     deg
```

### Commands
When the target temperature is changed manually on the room sensor, it sends that information to the controller. Similarily, the controller can send updates about the target temperature to the sensor (for example when temperature change is required as per the configured schedule). The controller also updates the room sensor when heating of the room starts or stops. The command type is 3-byte long and the value is 4-byte long and they all start with 06 which may indicate the length (see above - the parameters that are shorter by 2 bytes start with 04).
* 06 14 00 01 00 00 00 - heating started
* 06 14 00 00 00 00 00 - heating stopped
* 06 20 00 followed by 2 bytes indicating for how long the target temperature is set (in minutes) followed by 00 00 or ff ff ff ff (working according to the schedule)
* 06 21 00 followed by 2 bytes indicating the target temperature followed by 00 00
* 06 26 00 followed by 2 bytes indicating the time (or ff ff - schedule?) followed by 2 bytes indicating the target temperature (I'm not sure what's the difference between this paremeter and "06 20 00" & "06 21 00" - they seem to contain the same data / maybe some backward compatibility?)

Example
```
06 14 00 01 00 00 00 06 20 00 3b 00 00 00 06 21 00 e6 00 00 00 06 26 00 3b 00 e6 00
^^^^^^^  ^^^^^^^^^^^ ^^^^^^^^ ^^^^^^^^^^^ ^^^^^^^^ ^^^^^^^^^^^ ^^^^^^^^ ^^^^^^^^^^^
heating  ON          time     59 minutes  target   23 degrees  time     59 minutes
                                          temp                 & temp   23 degrees
```

### ACK
A node that received a message replies to the sender with an ACK message of the following structure:
```
ac ff ff ac 44 b5 cc 68
^^^^^^^^^^^ ^^^^^^^^^^^
const       CRC-32 of
            the data
            received
```

### Current date & time
Date and time is regularly transmitted by the central controller as follows:
```
3f a1 2e d0 24 94 6e 38 00 00 00 00
            ^^^^^^^^^^^
            Seconds from the Unix Epoch
            946770980 = Sat Jan  1 23:56:20 UTC 2000
```
