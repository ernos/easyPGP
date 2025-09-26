package com.yourdev.easypgp

import android.app.AlertDialog
import android.content.Context
import android.widget.EditText
import android.widget.LinearLayout

class PasswordDialog {

    interface PasswordCallback {
        fun onPasswordEntered(password: String)
        fun onPasswordCancelled()
    }

    companion object {
        fun showPasswordDialog(context: Context, title: String, message: String, callback: PasswordCallback) {
            val editText = EditText(context)
            editText.inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            editText.hint = "Enter your PGP key password"

            val layout = LinearLayout(context)
            layout.orientation = LinearLayout.VERTICAL
            layout.setPadding(50, 40, 50, 10)
            layout.addView(editText)

            val dialog = AlertDialog.Builder(context)
                .setTitle(title)
                .setMessage(message)
                .setView(layout)
                .setPositiveButton("OK") { _, _ ->
                    val password = editText.text.toString()
                    if (password.isNotEmpty()) {
                        callback.onPasswordEntered(password)
                    } else {
                        callback.onPasswordCancelled()
                    }
                }
                .setNegativeButton("Cancel") { _, _ ->
                    callback.onPasswordCancelled()
                }
                .setCancelable(false)
                .create()

            dialog.show()

            // Focus on the password field
            editText.requestFocus()
        }
    }
}
