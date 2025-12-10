package com.yourdev.easypgp

import android.app.AlertDialog
import android.content.Context
import android.widget.EditText
import android.widget.LinearLayout
import kotlinx.coroutines.suspendCancellableCoroutine
import android.app.Activity
import kotlin.coroutines.resume

class PasswordDialog {

    interface PasswordCallback {
        fun onPasswordEntered(password: String)
        fun onPasswordCancelled()
    }

    companion object {

        public fun showPasswordDialog(context: Context?, title: String, message: String, callback: PasswordCallback): String? {
            var retstr: String ?= null;
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
                        retstr=password;
                        callback.onPasswordEntered(password)
                    } else {

                        callback.onPasswordCancelled()
                        retstr = null;
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

            return retstr.toString();
        }

    }
}
