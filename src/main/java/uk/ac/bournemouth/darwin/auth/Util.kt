/*
 * Copyright (c) 2018.
 *
 * This file is part of ProcessManager.
 *
 * ProcessManager is free software: you can redistribute it and/or modify it under the terms of version 2.1 of the
 * GNU Lesser General Public License as published by the Free Software Foundation.
 *
 * ProcessManager is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even
 * the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with ProcessManager.  If not,
 * see <http://www.gnu.org/licenses/>.
 */

@file:JvmName("Util")

package uk.ac.bournemouth.darwin.auth

import android.arch.lifecycle.LifecycleOwner
import android.arch.lifecycle.LiveData
import android.arch.lifecycle.Observer
import android.databinding.BindingAdapter
import android.graphics.Typeface
import android.support.annotation.IntDef
import android.text.format.DateUtils
import android.widget.TextView
import java.nio.charset.Charset
import java.util.*


/** The UTF8 Character set  */
@JvmField
val UTF8 = Charset.forName("UTF-8")

@BindingAdapter("app:dateText")
fun setDateText(view: TextView, date: Date?) {
    if (date==null) {
        view.text = view.context.getString(R.string.lastUseNever)
    } else {
        view.text = DateUtils.getRelativeDateTimeString(view.context, date.time, DateUtils.SECOND_IN_MILLIS, DateUtils.WEEK_IN_MILLIS, 0)
//        view.text = DateUtils.formatDateTime(view.context, date.time, 0)
    }
}

@IntDef(value = [Typeface.NORMAL, Typeface.BOLD, Typeface.BOLD_ITALIC, Typeface.ITALIC])
annotation class FlagTextStyle

@BindingAdapter("android:textStyle")
fun setTextStyle(view: TextView, @FlagTextStyle textStyle: Int) {
    view.setTypeface(view.typeface, textStyle)
}

inline fun <T> LiveData<T>.observe(lifecycleOwner: LifecycleOwner, crossinline observer: (T?)->Unit) {
    return observe(lifecycleOwner, Observer { observer(it) })
}