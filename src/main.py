import os

import flet as ft

from services import firebase_client


def main(page: ft.Page):
    counter = ft.Text("0", size=50, data=0)
    fb = firebase_client.FirebaseClient()

    def increment_click(e):
        counter.data += 1
        counter.value = str(counter.data)
        counter.update()

    page.floating_action_button = ft.FloatingActionButton(
        icon=ft.Icons.ADD, on_click=increment_click
    )
    page.add(
        ft.SafeArea(
            ft.Container(
                counter,
                alignment=ft.alignment.center,
            ),
            expand=True,
        )
    )
    res = fb.get_user_by_field("username", "diego")
    page.add(
        ft.Text(res.type),
        ft.Text(os.getenv("FIREBASE_API_KEY")),
        ft.Text(os.getenv("FIREBASE_PROJECT_ID")),
    )


ft.app(main)
