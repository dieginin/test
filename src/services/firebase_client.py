import os
import re
import time

import requests

API_KEY = os.getenv("FIREBASE_API_KEY")
PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID")
DB_URL = f"https://{PROJECT_ID}-default-rtdb.firebaseio.com"


class FirebaseResponse:
    def __init__(self, type: str, message: str = "", data: dict | None = None) -> None:
        self.type = type
        self.message = message
        self.data = data or {}


class FirebaseClient:
    def __init__(self):
        self.api_key = API_KEY
        self.db_url = DB_URL

    # --- Helpers ---
    def __is_token_expired(self, token_info: dict) -> bool:
        expires_in = int(token_info.get("expiresIn", 0))
        created_at = int(token_info.get("createdAt", 0)) // 1000
        now = int(time.time())
        return now > (created_at + expires_in - 60)  # margen 60s

    def __refresh_token(self, refresh_token: str) -> FirebaseResponse:
        try:
            url = f"https://securetoken.googleapis.com/v1/token?key={self.api_key}"
            res = requests.post(
                url,
                data={"grant_type": "refresh_token", "refresh_token": refresh_token},
            )
            res.raise_for_status()
            return FirebaseResponse("success", data=res.json())
        except Exception as e:
            return FirebaseResponse("error", f"Refresh error: {str(e)}")

    def check_and_refresh_token(self, user_data: dict) -> FirebaseResponse:
        if self.__is_token_expired(user_data):
            refreshed = self.__refresh_token(user_data["refreshToken"])
            if refreshed.type == "success":
                return FirebaseResponse("refreshed", data=refreshed.data)
            else:
                return refreshed
        return FirebaseResponse("valid", data=user_data)

    # --- Auth ---
    def sign_up(
        self, email: str, username: str, display_name: str, role: str
    ) -> FirebaseResponse:
        # primero revisamos si username existe
        existing = self.get_user_by_field("username", username)
        if existing.type == "success" and existing.data:
            return FirebaseResponse("error", "Username already in use")
        try:
            url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={self.api_key}"
            payload = {
                "email": email,
                "password": "carefree",
                "returnSecureToken": True,
            }
            res = requests.post(url, json=payload)
            res.raise_for_status()
            user = res.json()
            # enviar verificación
            self.__send_email_verification(user["idToken"])
            # guardar usuario en DB
            self.__set_user(
                user["localId"],
                {
                    "uid": user["localId"],
                    "email": email,
                    "username": username,
                    "display_name": display_name,
                    "role": role,
                },
                id_token=user["idToken"],
            )
            return FirebaseResponse("success", "Verification email sent", data=user)
        except requests.exceptions.HTTPError as e:
            return FirebaseResponse("error", f"Email already in use or error: {str(e)}")

    def sign_in(self, email_or_username: str, password: str) -> FirebaseResponse:
        is_email = re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email_or_username)
        if is_email:
            email = email_or_username
        else:
            # buscar username
            user_resp = self.get_user_by_field("username", email_or_username)
            if user_resp.type != "success" or not user_resp.data:
                return FirebaseResponse("error", "Username not found")
            email = user_resp.data.get("email")
            if not email:
                return FirebaseResponse("error", "No email associated with username")
        try:
            url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={self.api_key}"
            payload = {"email": email, "password": password, "returnSecureToken": True}
            res = requests.post(url, json=payload)
            res.raise_for_status()
            data = res.json()
            # comprobar verificado
            acc_info = self.get_account_info(data["idToken"])
            if not acc_info.get("emailVerified"):
                return FirebaseResponse("error", "Email not verified")
            return FirebaseResponse("success", "Welcome back!", data)
        except requests.exceptions.HTTPError:
            return FirebaseResponse("error", "Invalid password")

    def send_password_reset_email(self, email: str) -> FirebaseResponse:
        try:
            url = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={self.api_key}"
            payload = {"requestType": "PASSWORD_RESET", "email": email}
            res = requests.post(url, json=payload)
            res.raise_for_status()
            return FirebaseResponse("success", "Password reset email sent")
        except requests.exceptions.HTTPError:
            return FirebaseResponse("error", "Error sending password reset email")

    def update_profile(
        self,
        id_token: str,
        display_name: str | None,
        username: str | None,
        role: str | None,
    ) -> FirebaseResponse:
        try:
            if display_name:
                self.__update_display_name(id_token, display_name)
            if username or role:
                uid = self.get_account_info(id_token)["localId"]
                update_data = {}
                if username:
                    update_data["username"] = username
                if role:
                    update_data["role"] = role
                self.__set_user(uid, update_data, id_token=id_token, merge=True)
            return FirebaseResponse("success", "Profile updated")
        except Exception:
            return FirebaseResponse("error", "Error updating profile")

    def delete_user(self, id_token: str) -> FirebaseResponse:
        try:
            uid = self.get_account_info(id_token)["localId"]
            url = f"https://identitytoolkit.googleapis.com/v1/accounts:delete?key={self.api_key}"
            res = requests.post(url, json={"idToken": id_token})
            res.raise_for_status()
            self.__delete_user(uid, id_token=id_token)
            return FirebaseResponse("success", "User deleted")
        except requests.exceptions.HTTPError:
            return FirebaseResponse("error", "Error deleting user")

    # --- Internos DB/REST ---
    def get_account_info(self, id_token: str) -> dict:
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={self.api_key}"
        res = requests.post(url, json={"idToken": id_token})
        res.raise_for_status()
        return res.json()["users"][0]

    def get_user_by_field(self, field: str, value: str) -> FirebaseResponse:
        try:
            url = f'{self.db_url}/users.json?orderBy="{field}"&equalTo="{value}"'
            res = requests.get(url)
            res.raise_for_status()
            data = res.json()
            if not data:
                return FirebaseResponse("success", data={})
            # devuelve el primero
            uid, val = next(iter(data.items()))
            return FirebaseResponse("success", data=val)
        except Exception as e:
            return FirebaseResponse("error", f"Error fetching user: {str(e)}")

    def __set_user(
        self, uid: str, data: dict, id_token: str | None = None, merge: bool = False
    ):
        auth_part = f"?auth={id_token}" if id_token else ""
        url = f"{self.db_url}/users/{uid}.json{auth_part}"
        if merge:
            requests.patch(url, json=data).raise_for_status()
        else:
            requests.put(url, json=data).raise_for_status()

    def __delete_user(self, uid: str, id_token: str | None = None):
        auth_part = f"?auth={id_token}" if id_token else ""
        url = f"{self.db_url}/users/{uid}.json{auth_part}"
        requests.delete(url).raise_for_status()

    def __send_email_verification(self, id_token: str):
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={self.api_key}"
        payload = {"requestType": "VERIFY_EMAIL", "idToken": id_token}
        requests.post(url, json=payload).raise_for_status()

    def __update_display_name(self, id_token: str, display_name: str):
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:update?key={self.api_key}"
        payload = {
            "idToken": id_token,
            "displayName": display_name,
            "returnSecureToken": True,
        }
        requests.post(url, json=payload).raise_for_status()
