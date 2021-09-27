# OneDriveSymLink: Make OneDrive Support SymLink

## How It Works

This project is also trying to make OneDrive sync outer symlink (i.e. symbolic links from within OneDrive to other place).

[ktheod/OneDriveBully](https://github.com/ktheod/OneDriveBully) is also trying to solve this problem, which creates a file at the root of OneDrive, making OneDrive using 2 cores of CPU if you have lots of files in your OneDrive.

However, this project works as a patcher, which hooks ReadDirectoryChangeW, and then implements custom directory watching logic.

In this way, we can make use of Windows own directory change notification, making the whole process much more efficient.

## Installation

- Copy VERSION.dll in Release into `C:\Users\<YOUR_USERNAME>\AppData\Local\Microsoft\OneDrive\`
- Restart OneDrive by killing the process and restart it

## Usage

- Create `symlinks.ini` under the root of your OneDrive
- Enter symlinks in the OneDrive like below. `OD\` corresponds to OneDrive's root
  ```
  OD\XXXXX
  ```
  
  So if you are marking OneDrive\Test\ as symbolic link, you would input:
  ```
  OD\Test
  ```
- After saving the `symlinks.ini`, restart OneDrive just like installation