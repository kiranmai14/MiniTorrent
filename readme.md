## MiniTorrent - A PEER-TO-PEER GROUP BASED FILE SHARING SYSTEM

A peer-to-peer group based file sharing system which runs on linux where users can share, download files from the group they belong to. Multiple pieces are downloaded from multiple peers parallelly.


### Architecture Overview:
The Following entities will be present in the network :
1. Tracker : <br/>
a. Maintain information of clients with their files(shared by client) to assist the
clients for the communication between peers

2. Clients: <br/>
a. User creates an account and register with tracker <br/>
b. Login using the user credentials <br/>
c. Create Group and he will become owner of that group <br/>
d. Fetch list of all Groups in server <br/>
e. Request to Join Group <br/>
f. Leave Group <br/>
g. Accept Group join requests (if owner) <br/>
h. Share file across group: Share the filename and SHA1 hash of the complete file  with the tracker <br/>
i. Fetch list of all sharable files in a Group <br/>
j. Download file <br/>
    i. Retrieve peer information from tracker for the file <br/>
    ii. Downloads file from multiple peers (different pieces of file from different peers - piece selection algorithm) simultaneously and all the files which client downloads will be shareable to other users in the same group. Ensures file integrity from SHA1 comparison <br/>
k. Show downloads <br/>
l. Stop sharing file <br/>
m. Stop sharing all files (Logout) <br/>
n. Whenever client logins, all previously shared files before logout should
automatically be on sharing mode <br/>

### commands:

1. Tracker:
```c++
a. Run Tracker: ./tracker tracker_info.txt tracker_no
b. Close Tracker: quit
```

tracker_info.txt - Contains ip, port details of tracker


<br/>

2. Client:
```c++
a. Run Client:                          ./client <IP>:<PORT> tracker_info.txt
b. Create User Account:                 create_user <user_id> <passwd>
c. Login:                               login <user_id> <passwd>
d. Create Group:                        create_group <group_id>
e. Join Group:                          join_group <group_id>
f. Leave Group:                         leave_group <group_id>
g. List pending join:                   requests list_requests <group_id>
h. Accept Group Joining Request:        accept_request <group_id> <user_id>
i. List all groups:                     list_groups
j. List all sharable files in Group:    list_files <group_id>
k. Upload File:                         upload_file <file_path> <group_id>
l. Download File:                       download_file <group_id> <file_name> <destination_path>
m. Logout:                              logout
n. Show_downloads:                      show_downloads
o. Stop sharing:                        stop_share <group_id> <file_name>
```


