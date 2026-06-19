# **Soshal API Reference**

This server is designed to act as the backend for both the Swipe-based UI and the Scroll-based UI. To ensure maximum flexibility for native and web-based client applications, **all endpoints are accessed via POST requests** using a JSON payload.

* **Base URL:** http://localhost:8000 (or your ngrok / local tunnel URL)  
* **Content-Type:** All requests must send application/json in the body.

## **Table of Contents**

1. [Authentication & Account Management](#bookmark=id.8nrexehgc3uu)  
   * [POST /api/signup](#bookmark=id.atc5bgdvc9x5)  
   * [POST /api/login](#bookmark=id.cauagug1l0kk)  
   * [POST /api/logout](#bookmark=id.kibeqq635dh5)  
2. [User Profiles & Social Network](#bookmark=id.e13ftrgoi9ze)  
   * [POST /api/users/profile](#bookmark=id.cza1ck6wze13)  
   * [POST /api/users/follow](#bookmark=id.8z5po3ty4se9)  
3. [Posts Management](#bookmark=id.qfkxwvrydlcz)  
   * [POST /api/posts/create](#bookmark=id.qh1gg4vpxs0i)  
   * [POST /api/posts/list](#bookmark=id.x3vjy4ivnd4s)  
   * [POST /api/posts/user](#bookmark=id.p1r3wqquiemj)  
   * [POST /api/posts/like](#bookmark=id.9v3s3iwdevql)  
4. [Search System](#bookmark=id.jndle1u4iher)  
   * [POST /api/search](#bookmark=id.unhpueh8kar6)

## **1\. Authentication & Account Management**

### **POST /api/signup**

Registers a new user and assigns a unique 5-character suffix (user\_id). This ID is salted into the PBKDF2 hash pipeline to ensure cryptographic uniqueness.

* **Authentication:** None required.  
* **Payload:**  
  {  
    "username": "MyCoolUser",  
    "password": "SuperSecretPassword123"  
  }

* **Success Response (201 Created):**  
  {  
    "message": "User created successfully"  
  }

* **Error Responses:**  
  * 400 Bad Request: {"error": "Username and password required"}  
  * 409 Conflict: {"error": "Username already exists"} (case-insensitive check)

### **POST /api/login**

Authenticates credentials and returns an active session token.

* **Authentication:** None required.  
* **Payload:**  
  {  
    "username": "MyCoolUser",  
    "password": "SuperSecretPassword123"  
  }

* **Success Response (200 OK):**  
  {  
    "message": "Login successful",  
    "token": "7V0Z8o4P9N...random\_urlsafe\_token..."  
  }

  *Save this token securely in client local storage to authorize subsequent endpoints.*  
* **Error Response (401 Unauthorized):**  
  {  
    "error": "Invalid username or password"  
  }

### **POST /api/logout**

Destroys the session token in the active server session store.

* **Headers:** Authorization: Bearer \<your\_session\_token\>  
* **Payload:** {} *(Empty JSON payload)*  
* **Success Response (200 OK):**  
  {  
    "message": "Logged out successfully"  
  }

## **2\. User Profiles & Social Network**

### **POST /api/users/profile**

Fetches the statistics, relationship state, and unique identifier associated with any user.

* **Headers:** Authorization: Bearer \<your\_session\_token\>  
* **Payload:**  
  {  
    "username": "AstroMe"  
  }

* **Success Response (200 OK):**  
  {  
    "username": "AstroMe",  
    "user\_id": "c8c2n",  
    "followers\_count": 14,  
    "following\_count": 42,  
    "is\_following": true,  
    "is\_self": false  
  }

* **Error Responses:**  
  * 401 Unauthorized: Token is missing, expired, or invalid.  
  * 404 Not Found: {"error": "User not found"}

### **POST /api/users/follow**

Follows or unfollows a targeted profile.

* **Headers:** Authorization: Bearer \<your\_session\_token\>  
* **Payload:**  
  {  
    "target\_user": "AstroMe",  
    "action": "follow"  
  }

  *Note: "action" must be either "follow" or "unfollow".*  
* **Success Response (200 OK):**  
  {  
    "message": "Successfully followed AstroMe"  
  }

* **Error Responses:**  
  * 400 Bad Request: {"error": "You cannot follow yourself."}  
  * 404 Not Found: {"error": "User not found"}

## **3\. Posts Management**

### **POST /api/posts/create**

Publishes a post. Supports inline text content, mentions, and base64 encoded media files.

* **Headers:** Authorization: Bearer \<your\_session\_token\>  
* **Payload:**  
  {  
    "content": "Check out this image\! @AstroMe\#c8c2n",  
    "image": "data:image/png;base64,iVBORw0KGgoAAAANS..."  
  }

  *Either content or image must be provided.*  
* **Success Response (201 Created):**  
  {  
    "message": "Post created",  
    "post": {  
      "id": "e4f8d48a-6b83-4705-83e8-5421a224a0d9",  
      "author": "MyCoolUser",  
      "content": "Check out this image\! @AstroMe\#c8c2n",  
      "image": "data:image/png;base64,iVBORw0KGgoAAAANS...",  
      "timestamp": 1781878432.54,  
      "likes": 0  
    }  
  }

### **POST /api/posts/list**

Retrieves a filtered, chronological timeline of posts from the server database.

* **Headers:** Authorization: Bearer \<your\_session\_token\>  
* **Payload:**  
  {  
    "limit": 20,  
    "feed\_type": "following"  
  }

  * "limit": Maximum number of posts to retrieve.  
  * "feed\_type": "global" (everyone's posts) or "following" (only posts made by users you follow).  
* **Success Response (200 OK):**  
  {  
    "posts": \[  
      {  
        "id": "e4f8d48a-6b83-4705-83e8-5421a224a0d9",  
        "author": "AstroMe",  
        "content": "A beautiful view out here\!",  
        "image": null,  
        "timestamp": 1781878432.54,  
        "likes": 12  
      }  
    \],  
    "is\_following\_empty": false  
  }

### **POST /api/posts/user**

Retrieves only the posts created by a specific targeted user.

* **Headers:** Authorization: Bearer \<your\_session\_token\>  
* **Payload:**  
  {  
    "username": "AstroMe",  
    "limit": 50  
  }

* **Success Response (200 OK):**  
  {  
    "posts": \[  
      {  
        "id": "e4f8d48a-6b83-4705-83e8-5421a224a0d9",  
        "author": "AstroMe",  
        "content": "A beautiful view out here\!",  
        "image": null,  
        "timestamp": 1781878432.54,  
        "likes": 12  
      }  
    \]  
  }

### **POST /api/posts/like**

Increments or decrements a post's global like counter. Safe against Path Traversal vulnerabilities via strict ID formatting checks.

* **Headers:** Authorization: Bearer \<your\_session\_token\>  
* **Payload:**  
  {  
    "post\_id": "e4f8d48a-6b83-4705-83e8-5421a224a0d9",  
    "action": "like"  
  }

  *Note: "action" must be either "like" or "unlike".*  
* **Success Response (200 OK):**  
  {  
    "message": "Like updated",  
    "likes": 13  
  }

* **Error Response (400 Bad Request):**  
  * {"error": "Invalid post ID format"} (If the post\_id is not a valid UUIDv4 structure)

## **4\. Search System**

### **POST /api/search**

Performs real-time indexed lookups matching user profiles or posts content.

* **Headers:** Authorization: Bearer \<your\_session\_token\>  
* **Payload:**  
  {  
    "query": "AstroMe",  
    "type": "users"  
  }

  * "type": "users" (matches usernames or user\_id suffixes) or "posts" (matches content body or authors).  
* **Success Response \- Users Type (200 OK):**  
  {  
    "results": \[  
      {  
        "username": "AstroMe",  
        "user\_id": "c8c2n",  
        "followers\_count": 14,  
        "following\_count": 42  
      }  
    \]  
  }

* **Success Response \- Posts Type (200 OK):**  
  {  
    "results": \[  
      {  
        "id": "e4f8d48a-6b83-4705-83e8-5421a224a0d9",  
        "author": "AstroMe",  
        "content": "A beautiful view out here\!",  
        "image": null,  
        "timestamp": 1781878432.54,  
        "likes": 12  
      }  
    \]  
  }  
