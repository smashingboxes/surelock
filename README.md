# surelock
Surelock aims to make Fingerprint authentication easy for developers.

With Surelock, all you have to worry about is:
1. **Where** you want to store your encrypted information  
2. And **when** you want to allow the user to use their fingerprint to encrypt that information.

And there's no need to check the Android version everywhere. That's handled for you!
Elementary, my dear Watson.

Download
--------

```groovy
dependencies {
  compile 'com.smashingboxes.surelock:0.1.0'
  compile 'com.android.support:appcompat-v7:LATEST_VERSION'
}
```
Snapshots of the development version are available in [Sonatype's `snapshots` repository][snap].

Getting Started
---------------
1. Create a new instance of Surelock in your activity's `onCreate` method
```java
Surelock surelock = Surelock.initialize(this, new SharedPreferencesStorage(this, SHARED_PREFS_FILE_NAME), KEYSTORE_KEY_ALIAS);
```
2. 

Compatibility
-------------
The FingerprintManager APIs are only supported on Android versions 23+
However, you can add Surelock to any project and check for compatibility with Surelock's helper methods.

NOTE: Samsung S5 and Note 4 devices do not support the Android FingerprintManager APIs, and therefore Surelock cannot support these devices.
Samsung S6 and newer devices which have Fingerprint Scanning hardware should work fine.


Built With
----------
* [Swirl](https://github.com/mattprecious/swirl) - Animated Fingerprint Icon

Authors
-------

* **Tyler McCraw** - *Architecture, baseline library, initial demo samples* - [TylerMcCraw](https://github.com/TylerMcCraw)
* **Nick Cook** - *Custom styling, Material Design dialog, validation, testing* - [nicholas-cook](https://github.com/nicholas-cook)

See also the list of [contributors](https://github.com/your/project/contributors) who participated in this project.

License
-------

    Copyright 2017 Smashing Boxes

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
    
[snap]: https://oss.sonatype.org/content/repositories/snapshots/