package com.yourdev.easypgp

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView

class ImportedKeysAdapter(
    private val keys: MutableList<ImportedPublicKey>,
    private val onDeleteClick: (ImportedPublicKey) -> Unit
) : RecyclerView.Adapter<ImportedKeysAdapter.KeyViewHolder>() {

    class KeyViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        val textViewName: TextView = itemView.findViewById(R.id.textViewKeyName)
        val textViewKeyId: TextView = itemView.findViewById(R.id.textViewKeyId)
        val buttonDelete: Button = itemView.findViewById(R.id.buttonDelete)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): KeyViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_imported_key, parent, false)
        return KeyViewHolder(view)
    }

    override fun onBindViewHolder(holder: KeyViewHolder, position: Int) {
        val key = keys[position]
        holder.textViewName.text = key.name
        holder.textViewKeyId.text = "Key ID: ${key.keyId}"
        holder.buttonDelete.setOnClickListener {
            onDeleteClick(key)
        }
    }

    override fun getItemCount(): Int = keys.size

    fun addKey(key: ImportedPublicKey) {
        keys.add(key)
        notifyItemInserted(keys.size - 1)
    }

    fun removeKey(key: ImportedPublicKey) {
        val index = keys.indexOf(key)
        if (index != -1) {
            keys.removeAt(index)
            notifyItemRemoved(index)
        }
    }
}
