# Forensic analysis

### Laboratory for the class “Cybersecurity” (01UDR)

### Politecnico di Torino – AA 2021/

### Prof. Antonio Lioy

### prepared by:

### Diana Berbecaru (diana.berbecaru@polito.it)

### Andrea Atzeni (andrea.atzeni@polito.it)

### v. 1.1 (07/12/2021)

## Contents

1 Purpose of this laboratory 1

#### 2 CAINE 2

3 Image acquisition 4

4 File identification 6

5 File carving 8

6 Data wiping 8

7 Additional exercises (optional) 10

## 1 Purpose of this laboratory

In this laboratory, you will perform exercises aimed to experiment with forensic analysis, specifically targeting
analysis of the storage.

The opinion that deleting a file or history through a command likermor dropping it in the Trash will remove
it completely from the hard disk drive is wrong. In reality, it only removes the file from the logical structures
that address it, but the actual file remains on your computer until overwritten due to (future) requests of storage
space from the OS and its applications.

### Additional software tools

The tools listed below will be used as well throughout this laboratory:

dd- ‘dd’ copies a file (from standard input to standard output, by default) to/from an I/O block size, while
optionally performing conversions on it.


```
Warning:Some people believe dd means “Destroy Disk” or “Delete Data” because if it is misused, a
partition or output file can be trashed very quickly. Sinceddis the tool used to write disk headers, boot
records, and similar system data areas, misuse ofddhas already caused enough pain...
```
dcfldd- ’dcfldd’ is an enhanced version of GNU dd with features useful for forensics and security. Based on
the dd program found in the GNU Coreutils package. It has some additional features particularly suited
for forensics analysis, likehashing-on-the-fly, flexible data-wipes and cloning verification
Home page =https://dcfldd.sourceforge.net/

exiftool- ExifTool is a platform-independent Perl library plus a command-line application for reading, writing
and editing meta information. Reads EXIF, GPS, IPTC, XMP, JFIF, MakerNotes, GeoTIFF, ICC Profile,
Photoshop IRB, FlashPix, AFCP, ID3, Lyrics3, ODT, DOCX. For a complete list of supported formats
seehttps://exiftool.org/#supported
Home page =https://exiftool.org

foremost- Foremost is a console program to recover files based on their headers, footers, and internal data
structures. This process is commonly referred to as data carving. Foremost can work on image files, such
as those generated by dd, Encase, etc, or directly on a drive
Home page =http://foremost.sourceforge.net/

photorec- PhotoRec is file data recovery software designed to recover lost files including video, documents
and archives from Hard Disks and CDRom and lost pictures (Photo Recovery) from digital camera mem-
ory. PhotoRec ignores the filesystem and goes after the underlying data, so it’ll work even if your media’s
filesystem is severely damaged or formatted
Home page=www.cgsecurity.org

First of all, for performing a forensics analysis, you have to create a trusted environment in which to perform
your analysis without be afraid of compromisison. You can choose two different way of perorming, both of
them valid from a digital forensic perspective: 1) run a live OS and move you evidences in there, or 2) run a
Virtual machine and insert the evidences inside the virtual environment (in this case, both host and guest OS
must be trusted).

In the first case, you can run Kali linux in the laboratory as usual.

If you want to experiment the second case, you can download CAINE (sec. 2) (we provided the last version of
the image inside Polito premises, that should allow a quick download from Labinf), run VirtualBox and use the
iso image to configure the virtual machine.

## 2 CAINE

CAINE (Computer Aided INvestigative Environment) is an Italian GNU/Linux live distribution created as a
Digital Forensics project in 2008, originally developed at the University of Modena and Reggio Emilia, specifi-
cally suited for Computer Forensics analysis (detailed history can be seen athttps://www.caine-live.net/
page4/history.html)

As a distro, it integrates software tools as modules along with powerful scripts in a GUI. In figure. 1 you can
see the appearance of the running live.

The first operation to perform the laboratory is to download the ISO image of the last version; a mirrored image
can be found here:

https://storage-sec.polito.it/external/caine/2020/caine11.0.iso

Since the integrity and the accuracy of working tool is of the uttermost importance in a forensics analysis, the
first thing to do is to check the status of the instruments used. Different hash computation of the ISO image are
the following:


```
Figure 1: CAINE v
```
MD5 - 73EA6E4F3B1861EFC1472B891DFA1255 caine11.0.iso
SHA1 - 74E059AF4547CB5D765080BDB8B236E4CB4550AE caine11.0.iso
SHA256 - 30a3cdf4012f08317eacc562f1b1b120e39ea5fda6c8772a95e32f3be8183d0c caine11.0.iso

### Virtual Box

After that, you can run Live CAINE from an ISO file by mounting it on the virtual DVD of an ad hoc VM. Fol-
low the instructions we have provided in the “general laboratory instructions” in the text of the first laboratory,
in the section 2.1.2. The only change is that you have to usecaine11.0.isoas DVD image.

Note: experiments have shown unexpected malfunction if the VM has low RAM capacity. The advice is to
choose 4 GB or more, and in any case no less than 2 GB.

### Adding a Virtual disk

After the creation of a VM, in order to make available another device to attach other images, you need to define
a new empty virtual disk in the virtual box set-up. To this aim, you need to perform the following steps:

1. select the CAINE VM (before starting it)
2. select the iconSettingsand then selectStorage
3. add a newIDEvirtual hard disk by clicking on theAdds Hard Diskfile on the right ofController:IDE
    row
4. Createa newVirtualBox Disk Image (VDI)choosing 5 GB as HD size, and thenChooseit in order
    to attach to the current VM

In this way, inside CAINE another device corresponding to the virtual one will be present.

```
N.B.
In Caine you must open gparted and create a partition and a file system on the disk given by virtualbox, then mount it to /dev/sda1, and then it can be accessed.
```
## 3 Image acquisition

### Status of the Virtual Environment

In a Computer Forensics analysis, it is very important to avoid accidental modification of the evidence and data
under analysis. To avoid data modification, almost all Linux-based recent distribution suitable for Computer
Forensic uses a default read-only mounting of the present devices (this is true for CAINE and for Kali in
forensic mode).

Take awareness of the present initial condition your system:

- Linux environments allow multiple possibilities to investigate and manage file system structure. From
    a command-line tool perspective, a direct way to acquire info on devices and partition is thefdisk
    command-line tool, and information on its usage can be found through the commandman fdisk.
    Write the syntax to see the available device(s) throughfdisk.

```
> sudo fdisk -l
Disk /dev/sda: 931,53 GiB, 1000204886016 bytes, 1953525168 sectors
Disk model: HGST HTS541010A9
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 4096 bytes
I/O size (minimum/optimal): 4096 bytes / 4096 bytes
Disklabel type: gpt
Disk identifier: 5AAAC3A8-4B36-4831-8791-8B6DD3282C1E

Device     Start        End    Sectors   Size Type
/dev/sda1   2048 1953523711 1953521664 931,5G Microsoft basic data


Disk /dev/sdb: 465,78 GiB, 500107862016 bytes, 976773168 sectors
Disk model: Samsung SSD 850 
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: gpt
Disk identifier: 6B093694-4ED2-4BFD-A445-AAF710C7BE61

Device         Start       End   Sectors   Size Type
/dev/sdb1       2048    206847    204800   100M EFI System
/dev/sdb2     206848    239615     32768    16M Microsoft reserved
/dev/sdb3     239616 628856261 628616646 299,8G Microsoft basic data
/dev/sdb4  628856832 629915647   1058816   517M Windows recovery environment
/dev/sdb5  629915648 825227263 195311616  93,1G Linux filesystem
/dev/sdb6  825227264 976771071 151543808  72,3G Linux filesystem
```
CAINE
```
caine@caine:/tmp$ sudo fdisk -l
Disk /dev/loop0: 3,7 GiB, 3928313856 bytes, 7672488 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/loop1: 511 MiB, 535805952 bytes, 1046496 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x00000000


Disk /dev/sda: 8 GiB, 8589934592 bytes, 16777216 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: gpt
Disk identifier: 25851D6B-66A5-5D4D-80A9-8862029D8479

Device     Start      End  Sectors Size Type
/dev/sda1   2048 16775167 16773120   8G Linux filesystem
```
List all available virtual devices in the system, and identify the virtual device suitable for your investiga-
tion.

A virtual device, in operating systems like Unix or Linux, refers to a device file that has no associated hardware. This type of file can be created with the mknod command, for instance. A virtual device mimics a physical hardware device when, in fact, it exists only in software form. Therefore, it makes the system believe that a particular hardware exists when it really does not.
A virtual device is also known as a virtual peripheral.
Initially, the command mknod was used to produce the character and block devices that populate the "/dev/" directory. But now the udev device manager automatically creates and destroys device nodes in the virtual file system. The supposed hardware (virtual device) is detected by the kernel, but, actually, it is only a file/directory.

```
/dev/sda1: 1tb data hdd
/dev/sdb3: Windows ssd
/dev/sdb5: Linux / ssd
/dev/sdb6: Linux /home ssd
```
Identify if they are in read-write or read-only state. Pay attention that the question is not if they are
mountedin read-only or read-write mode (that could be investigated by using the mount command), but
instead if thedeviceis in read-only or read-write state. To investigate that, you can use theblockdev
command:
blockdev --report devicename
and check the result of the first column (romeans read-only,rwmeans writable).

```
> mount | grep "/dev"
udev on /dev type devtmpfs (rw,nosuid,noexec,relatime,size=3972272k,nr_inodes=993068,mode=755)
devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000)
/dev/sdb5 on / type ext4 (rw,relatime,errors=remount-ro)
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)
cgroup on /sys/fs/cgroup/devices type cgroup (rw,nosuid,nodev,noexec,relatime,devices)
mqueue on /dev/mqueue type mqueue (rw,nosuid,nodev,noexec,relatime)
hugetlbfs on /dev/hugepages type hugetlbfs (rw,relatime,pagesize=2M)
/dev/sdb3 on /mnt/589ACBE49ACBBD2E type fuseblk (rw,relatime,user_id=0,group_id=0,default_permissions,allow_other,blksize=4096)
/dev/sdb6 on /home type ext4 (rw,relatime)
/dev/sdb1 on /boot/efi type vfat (rw,relatime,fmask=0077,dmask=0077,codepage=437,iocharset=iso8859-1,shortname=mixed,errors=remount-ro)
/dev/sda1 on /mnt/26158F5879578F52 type fuseblk (rw,relatime,user_id=0,group_id=0,default_permissions,allow_other,blksize=4096)
/dev/fuse on /run/user/1000/doc type fuse (rw,nosuid,nodev,relatime,user_id=1000,group_id=1000)

(all interesting devices are mounted in read-write mode)
```
```
caine@caine:~$ sudo mount
/tmp/image2021.dd on /mnt/imagedd type vfat (rw,relatime,fmask=0022,dmask=0022,codepage=437,iocharset=iso8859-1,shortname=mixed,errors=remount-ro)
/dev/sda on /media/sda type vfat (ro,nodev,noexec,noatime,fmask=0000,dmask=0000,allow_utime=0022,codepage=437,iocharset=iso8859-1,shortname=mixed,quiet,errors=remount-ro)
```
```
> sudo blockdev --report /dev/sda1 /dev/sdb3 /dev/sdb5 /dev/sdb6
RO    RA   SSZ   BSZ   StartSec            Size   Device
rw   256   512  4096       2048   1000203091968   /dev/sda1
rw   256   512  4096     239616    321851722752   /dev/sdb3
rw   256   512  4096  629915648     99999547392   /dev/sdb5
rw   256   512  4096  825227264     77590429696   /dev/sdb6

(all interesting devices are in read-write state)
```
```
caine@caine:~$ sudo blockdev --report /dev/loop0 /dev/sda
RO    RA   SSZ   BSZ   StartSec            Size   Device
ro   256   512  1024          0      3928313856   /dev/loop0
ro   256   512  4096          0      5368709120   /dev/sda
```

### Acquisition of the image

A very common task in a Computer Forensics analysis is the acquisition of part of a storage/hard disk in order to
perform deep analysis. In Linux environment two main possible option exists: 1) to acquire a physical storage,
physically integrate it, and see it as a device to connect to the file system (e.g. by mounting them),or 2) the
original storage can be deposited in a single file that contains the whole content and file system structure inside
(using tools likeddand the forensics counterparts).

In case a file containing a valid file system is available, a possibility to investigate it is by using a functionality
to mount these images files as valid block devices. Many Forensics Linux distribution provides some GUI
interfaces to do that (likeDisk Image Mounterfor CAINE). Those commands use theloopinterface for
devices. Loop devices are artefacts that allow access to a file in the same way of accessing to a block device.
This is achieved by introducing a pseudo-block device (theloopone) as intermediary to access to the original
file. At OS level, the operations (read,write,... ) to the mounted directory will be re-directed versus the loop


device, which will transparently translate the requests into operation to the original file. When theloopdevice
is already enabled (like in CAINE and Kali) it can be directly used through themountcommand:

```
caine@caine:/tmp$ sudo mkdir /mnt/imagedd
caine@caine:/tmp$ sudo mount -o loop image2021.dd /mnt/imagedd/
caine@caine:/tmp$ ls /mnt/imagedd/
 000_0021.jpg
 51416730324_4f75d9cb2c_k.jpg
 Aforismi_e_biblio_AldaMerini.docx
 Aforismi_e_biblio_AldaMerini.txt
 fmCJioB0XOv1JlyFVhSO22d9xggiggWj146T8kOE.mp4
 IMG_20190809_172632.jpg
 notepad.exe
 very.mysterious
 whatpf.mov
'WhatsApp Image 2020-12-19 at 11.21.29.jpeg'
```
wheremountingdirectorymust be an existent directory (e.g./media/imagedd). Note that if you runfdisk -l
before and after themountcommand, you may appreciate the presence of a new/dev/loopdevice, which is
the interface betweenimage.ddand themountingdirectory.

Now, let’s acquire our image: download it at the following URL:

https://storage-sec.polito.it/external/caine/2020/image2021.dd

and then check if the download did not introduce errors (or even if a malicious user manipulated it) by compar-
ing the result of the download with the following digests:

MD5 - b80cdd38f67761b4bf00a75838cd4745 image2021.dd
SHA1 - e8336744d56e7c8627ae11bcb1d40add43308001 image2021.dd
SHA256 - 048aa27d608ab6e6b342e947ef86d1a28c7d9781d1e28f6d4d43d99ddff7bb22 image2021.dd

```
To put the gracious file in the gracious vm I used
scp caine@10.0.2.10 image2021.dd /tmp
after downloading it in another vm with access to guest additions,
since there was not enough space anywhere else
```

If everything is fine, a possible next step is to clone the image on a virtual device to further examine it.

To do so, you can use thedata dump (dd)command indicating as source the image file, and as destination
your virtual device.

```
caine@caine:/tmp$ sudo dd if=image2021.dd of=/dev/sda
1046496+0 records in
1046496+0 records out
535805952 bytes (536 MB, 511 MiB) copied, 22,4833 s, 23,8 MB/s

caine@caine:/$ sudo fdisk -l
Disk /dev/loop0: 3,7 GiB, 3928313856 bytes, 7672488 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/loop1: 511 MiB, 535805952 bytes, 1046496 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x00000000


Disk /dev/sda: 8 GiB, 8589934592 bytes, 16777216 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x00000000

caine@caine:/$ cat /etc/fstab
/dev/sr0        /media/sr0      iso9660  ro,loop,noauto,noexec,nodev,noatime 0 0 # by rbfstab
/dev/sda        /media/sda      vfat     ro,loop,noauto,noexec,nodev,noatime,umask=000,shortname=mixed,quiet 0 0 # by rbfstab

caine@caine:/$ sudo mount /media/sda
```

```
Now we have the same image content in image2021.dd, /media/sda and in /dev/imagedd



caine@caine:/tmp$ findmnt -bno size /mnt/imagedd 
535805952
caine@caine:/tmp$ findmnt -bno size /media/sda 
53580595

```
Where thevirtualdeviceis the device defined in the virtual box setup and identified in a previous step (e.g.
/dev/sda). After the above command, a useful check again is checking that no errors have been introduced. A
first rough check is that the number of input bytes is the same of the number of output bytes (these messages
are provided bydditself)

To check the integrity, do you think the above control is enough?

```
No, we should check the integrity of the image before and after the dd operation.
```
If you think it is not enough, what commands do you suggest to use in addition?

```
1) openssl dgst -sha256 image.dd ; dd if=image.dd of=/dev/sda ;dd of=Newimage.dd if=/dev/virtualdevice ; openssl dgst -sha256 Newimage

2) dcfldd 
```
Alternatively, you might use thedcflddtool that can automate the copy and the hash evaluation in a single
step:

```
dcfldd if=image.dd of=/dev/virtualdevicehash=md5,sha1,sha256 md5log=image.md
sha1log=image.sha1 sha256log=image.sha
```
where thevirtualdeviceis the device defined in the virtual box setup and which has been identified in a previous
step.

Now try to mount the freshly created device. CAINE inserts in the/etc/fstaban entry that maps devices in
the/devto a corresponding directory in/media(e.g./dev/sda1is mapped on/media/sda1), so you can just
use a command like:

```
mount /media/virtualdevice
```
If everything went well, you can move inside that directory and explore the content of the disk.

Do you think that the “cloning” process performed withddonimage.ddcan be done with every kind of image?


```
No, only on images that contains a working filesystem.
```

hint: by using thefilecommand on the imageimage.ddyou can have some clues

What is the file system ofimage.dd?

```

caine@caine:/tmp$ file image2021.dd 
image2021.dd: DOS/MBR boot sector, code offset 0x58+2, OEM-ID "mkfs.fat", sectors/cluster 8, Media descriptor 0xf8, sectors/track 63, heads 255, hidden sectors 1050624, sectors 1048576 (volumes > 32 MB), FAT (32 bit), sectors/FAT 1024, reserved 0x1, serial number 0xaefc60c5, unlabeled
```
NOTE: in principle, you can create an image file from a virtual device using the same command, just reverting
input and output

```
dd of=image.dd if=/dev/virtualdevice
```
However, in this case you should know the size of the image and use it as parameter in the command. For
example, you can usefindmntcommand-line tool to query the mounted device (in particular, withfindmnt
-bno sizemountdiryou will find out also the size of the device), check the sector size of the device (e.g.
withfdisk -ltaking note of the sector size of the device) and then use the resulting knowledge to instruct the
ddcommand, for example:

```
dd if=virtualdevice, of=image.dd bs=sectorsizecount=numberofsectors
```
## 4 File identification

### Meta-data analysis

Now that your environment is ready and you have acquired the data to be analysed, it is time to start the analysis
phase. Go into themounteddirectoryand have a look at the content.

By using specific commands to analyse meta-data likeexiftoolwalk through all the files and perform the
following tasks:

- identify the file type;
- annotate interesting data about each file (e.g. creation date, last modification);
- note down any suspect detail that you encountered.

```
-rwxrwxrwx 1 root root 14953734 dic 19  2020  000_0021.jpg*
-rwxrwxrwx 1 root root   699104 dic  6 13:50  51416730324_4f75d9cb2c_k.jpg*
-rwxrwxrwx 1 root root    40181 dic 19  2020  Aforismi_e_biblio_AldaMerini.docx*
-rwxrwxrwx 1 root root    18943 dic 19  2020  Aforismi_e_biblio_AldaMerini.txt*
-rwxrwxrwx 1 root root  2250465 dic 19  2020  fmCJioB0XOv1JlyFVhSO22d9xggiggWj146T8kOE.mp4*
-rwxrwxrwx 1 root root  3339493 dic 19  2020  IMG_20190809_172632.jpg*
-rwxrwxrwx 1 root root   179712 dic  6 11:59  notepad.exe*
-rwxrwxrwx 1 root root    62980 dic 19  2020  very.mysterious*
-rwxrwxrwx 1 root root   171312 dic 19  2020  whatpf.mov*
-rwxrwxrwx 1 root root   175437 dic 19  2020 'WhatsApp Image 2020-12-19 at 11.21.29.jpeg'*
```

```
caine@caine:/media/sda$ file *
000_0021.jpg:                                 PC bitmap, Windows 3.x format, 2580 x 1932 x 24
51416730324_4f75d9cb2c_k.jpg:                 JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 2048x1536, frames 3
Aforismi_e_biblio_AldaMerini.docx:            Microsoft OOXML
Aforismi_e_biblio_AldaMerini.txt:             UTF-8 Unicode (with BOM) text, with very long lines
fmCJioB0XOv1JlyFVhSO22d9xggiggWj146T8kOE.mp4: Audio file with ID3 version 2.3.0, contains:MPEG ADTS, layer III, v1, 192 kbps, 44.1 kHz, JntStereo
IMG_20190809_172632.jpg:                      JPEG image data, Exif standard: [TIFF image data, big-endian, direntries=16, height=4160, bps=0, width=3120], baseline, precision 8, 3120x4160, frames 3
notepad.exe:                                  PE32 executable (GUI) Intel 80386, for MS Windows
very.mysterious:                              pcap-ng capture file - version 1.0
whatpf.mov:                                   PDF document, version 1.4
WhatsApp Image 2020-12-19 at 11.21.29.jpeg:   JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, progressive, precision 8, 1200x1600, frames 3
```
| file name                                    | file type declared | real file type                | suspect details                                                                                               |
| -------------------------------------------- | ------------------ | ----------------------------- | ------------------------------------------------------------------------------------------------------------- |
| 000_0021.jpg                                 | jpg                | PC bitmap                     | can't open                                                                                                    |
| 51416730324_4f75d9cb2c_k.jpg                 | jpg                | jpg                           |                                                                                                               |
| Aforismi_e_biblio_AldaMerini.docx            | docx               | docx (ooxml)                  |                                                                                                               |
| Aforismi_e_biblio_AldaMerini.txt             | txt                | UTF-8 Unicode (with BOM) text |                                                                                                               |
| fmCJioB0XOv1JlyFVhSO22d9xggiggWj146T8kOE.mp4 | mp4                | mp3                           |                                                                                                               |
| IMG_20190809_172632.jpg                      | jpg                | jpeg                          | Il vero regalo sono le scatole per fare ordine 2018                                                           |
| notepad.exe                                  | exe                | exe                           |                                                                                                               |
| very.mysterious                              | pcap               | pcap                          | Roku smart tv communication with a password in clear, a name of an HP computer and an ssid of a vodafone wifi |
| whatpf.mov                                   | mov                | pdf                           |                                                                                                               |
| WhatsApp Image 2020-12-19 at 11.21.29.jpeg   | jpeg               | jpeg                          |                                                                                                               |
```
File on disk is slightly different from size in the files: 514.., aforismi.docx, aforismi.txt, notepad.exe,very.misterious, whatpf.mov, whatsappimage.
```
```

000

Error interpreting JPEG image file (Not a JPEG file: starts with 0x42 0x4d)

binwalk:

9535811       0x918143        StuffIt Deluxe Segment (data): fRghTiiWjjZkhZhgYjjZiiWkjUjkQjlOkmOkmPlmSnnVnmXnmYonZrn[so\uo\tp]sr^ts_uq^uo\un]vp]uq^tq\rq\rrZtrZsqYvrZwr]ur]ts^ru\qv[su_su_tv`
9543536       0x919F70        StuffIt Deluxe Segment (data): fRefRghTfgSefRegQfgShiUhhVhhVhhXkkYjkWjiTjkQikNjlOkmPlmSlmSmmUnnVnmXqnYroZuo\so\rq]sr^uq_un]un]wp_vr_uq^rq\rq\trZsqYvq\wr]uq^ts^
9543548       0x919F7C        StuffIt Deluxe Segment (data): fRegQfgShiUhhVhhVhhXkkYjkWjiTjkQikNjlOkmPlmSlmSmmUnnVnmXqnYroZuo\so\rq]sr^uq_un]un]wp_vr_uq^rq\rq\trZsqYvq\wr]uq^ts^ru\rv]tv`su_
9922781       0x9768DD        lrzip compressed data
```

Are you able to delimit/individuate the time frame of activity for the device?

```
Date modified is 6 dec 2021 for 514.. and notepad.exe, while it is 19 dic 2020 for the others (between 13:04 and 14:01)
```

In the assumption this image is the exact content of a seized Hard Disk image, in your opinion does the CF
agents that seized the device made any mistake?

```
It is possible since there is so much difference in 2 files.
```
### File signature

Most of the known file formats can be identified by the few starting (and sometimes ending) bytes

A comprehensive list of file signature is publicly available athttps://en.wikipedia.org/wiki/List_of_
file_signatures.

Open the.mp4file with and hex viewer (e.g.hexdump,hexedit,ghex) and compare the first three bytes with
the file signatures in the file signature map. It confirms your beliefs?

```
As the file command suggests, it is not a .mp4 file (66 74 79 70 69 73 6F 6D	ftypisom	4	mp4	ISO Base Media file (MPEG-4)) but it is a .mp3 file (49 44 33	ID3	0	mp3	MP3 file with an ID3v2 container)
```
The command line utilityfileautomatically performs the check against the signature, so it can be used to
perform the check that has been performed at hand in the previous point thanks to the hex viewer.

Check all the files under exam withfileand annotate if the identification at the previous point is confirmed or
changed.

```
yes
```
Finally, if you did not annotate this in previous points, try to determine the program that created each file.
Optionally, also try to determine if any manipulation has been done on the different files present on the Hard
Disk. Another helpful command in this operation is thestringscommand line tool, which allow to find out
the different strings in a target file. Often, this allows for further information in a not very well know possible
source of data.

```
At the end of fmCJioB0XOv1JlyFVhSO22d9xggiggWj146T8kOE.mp4 there is LAM3.100 -LI4 LAM3.100UUUUUUUUUUUUUU repeated many times
```

By the way, while you are trying to discover creator ofvery.mysterious, have you noticed anything strange?

```
In very.interesting pcap file:
Intel(R) Core(TM) i7-7600U CPU @ 2.80GHz (with SSE4.2)
Linux 4.15.0-121-generic
Dumpcap (Wireshark) 2.6.10 (Git v2.6.10 packaged as 2.6.10-1~ubuntu18.04.0)
wlp2s0mon
Linux 4.15.0-121-generic
0H`l
shocked-HP-EliteBook-850-G4
0H`l;
0H`l
IwilCleverlyHideASecretHere
0H`l;
cR#b
noOneFillFindItah-ah-ah-ahh
0H`l;
myPassIsEvilAndSmartttttttt
0H`l;
Redmi6
I love Roku
shocked-HP-EliteBook-850-G4
$v33
c7'Pbn#
$v !
1s@ 
$v33
5v`}
$v0!
$v33
N5HN
yR)<
ps<X
$v@!
$v33
JWZh
l=~	
%kwG
$vP!
sBf98
8XA5
dY'Y
-4:5
$v`!
android-dhcp-97
3:;+
Tdfg
aS'{
9bB0
4_i-
S<2h
z;6^
$vp!
android-dhcp-97
3:;+
VodafoneMobileWiFi-AAE509
Ridotta
_ipps
_tcp
local
_ftp
_webdav
_webdavs
	_sftp-ssh
_smb
_afpovertcp
_nfs
_ipp
_ipps
_tcp
local
_ftp
_webdav
_webdavs
	_sftp-ssh
_smb
_afpovertcp
_nfs
_ipp
D\D\
0{"version": [2, 0], "port": 17500, "host_int": 27977691726034825087672340202697011740, "displayname": "", "namespaces": [1324081698, 1556320739, 1421316711, 1486077354, 7780612848, 1549959634, 1375292157]}
Xd.Ju
D8Swb
shocked-HP-EliteBook-850-G4
0H`l;
shocked-HP-EliteBook-850-G4
0H`l;
shocked-HP-EliteBook-850-G4
0H`l;
 Sr/
.b)e
8}%,
```

## 5 File carving

At this point you should have a pretty good knowledge of what were the files, and possibly the file content, of
the visible information contained in the image... but what about theinvisiblecontent (i.e. deleted files)?

Deleted files can be a very rich source of information, but to recover them the file system structure have to be
partially or totally bypassed (e.g. do not rely on allocation table). CAINE provides tools that do not rely on the
file system structures to identify information, likeforemost.

The process of extracting data from a device or disk image is namedcarving, meaning that the data comes
out from a non-shaped image like sculptures from the stone (in this case the “sculptures” assume the form of,
for example, .jpeg, .png, .zip, .pdf, files). We will instructforemostto carve how many files as it can with the
following command:

foremost -t all -i virtualdevice-o recoverydirectory-v
.

- -tset the file types to carve out,allmeans any supported file by foremost
- -iis specifying the input, which can be an image file or a device
- -ois the output directory, where the carved result will be placed. Inside the recovery directory foremost
    will create a set of directory for each file type will be able to recover
- -vlog all the messages to an audit report (inside the recovery directory) instead of standard output)

What is the output? Has foremost been able to bring up new information?

```
yes
```
Another powerful tool for data carving present in many CF distribution (like CAINE and Kali) isphotorec. To
execute it at best, some previous knowledge on the target of examination is expected, e.g. the file system type.
Since you should alredy posses all required info from previous steps of this lab, you can execute the following
command:

```
photorec /dev/sda
```

```
photorec /dev/loop1
```

And provide the required info, restricting the research to the unallocated space

Compare the result with foremost ones. Do you notice any difference?

```
photorec_report/recup_dir.1/f0046376.rtf
Luca, my old and dearest friend, I wait so long before express what I really feel. Still, I can accept to send it to you only disguised thanks to steghide program! You will find it in the place when we first meet, years ago. I desperately hope you will be able to find and appreciate it. Yours, Alice

foremost was not able to find different files!
```
## 6 Data wiping

To begin a new investigation, the testbed should be left perfectly clean to avoid pollution of the evidences of
the next case.


To remove any trace of the evidence on the virtual device used so far, the commanddcflddcan be used again.
In this case, to perform data wiping. It allows overwriting every byte of the target device with a specific pattern.
A sequence of zeros will perfectly accomplish the goal:

```
dcfldd pattern=00 of=virtualdevice
```
After this operation, are you still able to mount the device?

```
no
```
Are you still able to identify the file system?

```
no
```
Try to perform some recovery task (e.g.foremostorphotorec) and/or analyze the content with an hex viewer.
Is there any sign of the previous data?

```
no
```

## 7 Additional exercises (optional)

## Trying to hide the traces...

```
Exploiting the knowledge acquired in the previous exercises, prepare an image of 768 MB, and perform
some file operations (e.g. creation and modification). Then, try to obfuscate the information related to
those operations. For example, you might create and manipulate a picture, and then modify the picture
details and metadata (e.g. creation time)
The image must accomplish the following requirements
```
- must have a well-known file system
- must contain one or more files
- must have a size that makes possible save them in a set of USB pen drives of 256 MB

```
The purpose of this exercise is to create, manipulate and alter the files and their appearance to make
them complex to be identified, exploiting the tools used in the previous sections of this lab.
Then, you can transfer the image to your classmate and, she/he has to analyse the image and try to find
out
```
- the file system type
- the number of files (including the cancelled ones)
- the number of attempts to conceal/manipulate the original information related to the files
- the details of the attempts (e.g. “the file extension has been changed from ”.mov“ to ”mp4“)

```
And at the same time, you can get an image built by your classmate, and perform the same task
```
```
→
```
```
Finally, compare your result with the one of your classmates, and see who found most clues :)
```

