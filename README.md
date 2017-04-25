# Packet Capture And Analysis using C

Code written in partial fulfilment of **Course Computer Networks (CS F303). BITS Pilani, Pilani Campus. (Jan-May 2017)**

It currently works only in **Linux** based systems. It is tested in **Ubuntu 17.04** but should work fine with older versions of Ubuntu also.

### To Compile and run the program

#### To Compile
```
gcc main.c -o capture
```

#### To Run
```
sudo ./capture
```
*Note: The program needs sudo permission for opening the sock to capture packets*

### Running the Program

* In the beginning the program will ask you to enter a file name where it should print the details of the packets captured. Enter any file name here (eg. log.txt)
* Then it will ask for number of packets to be captured for analysis
* Then it will start capturing and once the desired number of packets are captured, Analysis prompt will be given to user.

### The Program gives following Options for analysis
1. Print all captured packets
> It prints the details of all the packets that are captured

2. Filter packets
   1. Filter by MAC address
   > Gives a list of all MAC addresses whose packets were captured. You can select
   > any one MAC address to filter.
  
   2. Filter by IP
   > Gives a list of all IP addresses whose packets were captured. You can select
   > any one IP address to filter.
  
   3. Filter by Protocol
   > You can select to filter only HTTP or FTP packets that were captured 
  
   4. Back to main menu

3. Display Network Traffic Graph
   > Creates "Number of packets captured vs Time" graph using gnuplot
   
   > *Note: **gnuplot** must be installed in your system for this option to work* .
   >  To install **gnuplot** in ubuntu run ```sudo apt-get install gnuplot```

4. Exit
