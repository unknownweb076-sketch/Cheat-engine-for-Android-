package com.venice.memscan

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView

class ResultAdapter(
    private val onWrite: (Long) -> Unit,
    private val onFreeze: (Long, Boolean) -> Unit
) : RecyclerView.Adapter<ResultAdapter.Holder>() {

    private val items = ArrayList<Pair<Long, Long>>()
    var type: Int = Scanner.TYPE_I32

    fun submit(data: List<Pair<Long, Long>>) {
        items.clear()
        items.addAll(data)
        notifyDataSetChanged()
    }

    override fun getItemCount() = items.size

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
        val v = LayoutInflater.from(parent.context).inflate(R.layout.item_result, parent, false)
        return Holder(v)
    }

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val (addr, valBits) = items[position]
        holder.addr.text = "0x" + addr.toString(16)
        holder.value.text = Scanner.formatValue(type, valBits)
        holder.write.setOnClickListener { onWrite(addr) }
        holder.freeze.setOnCheckedChangeListener(null)
        holder.freeze.isChecked = false
        holder.freeze.setOnCheckedChangeListener { _, checked -> onFreeze(addr, checked) }
    }

    class Holder(v: View) : RecyclerView.ViewHolder(v) {
        val addr: TextView = v.findViewById(R.id.addrText)
        val value: TextView = v.findViewById(R.id.valueText)
        val write: View = v.findViewById(R.id.writeBtn)
        val freeze: CheckBox = v.findViewById(R.id.freezeBox)
    }
}
