package uk.ac.bournemouth.darwin.auth

import android.os.Parcelable
import kotlinx.android.parcel.Parcelize
import org.xmlpull.v1.XmlPullParser
import java.util.*


@Parcelize
data class AccountInfo(
        val username: String,
        val alias: String?,
        val fullname: String?,
        val isLocalPassword: Boolean,
        val keys: List<KeyInfo>,
        val lookupTimeMs: Long = System.currentTimeMillis()): Parcelable {

    companion object {
        @JvmStatic
        fun from(reader: XmlPullParser): AccountInfo {
            assert(reader.eventType == XmlPullParser.START_TAG && reader.name=="account")

            val username = reader.getAttributeValue(null, "username")!!
            val alias = reader.getAttributeValue(null, "alias")
            val fullname = reader.getAttributeValue(null, "fullname")
            val isLocalPassword = reader.getAttributeValue(null, "isLocalPassword")!="no"

            val keys = generateSequence({reader.nextTag().let { if (it==XmlPullParser.END_TAG) null else it }})
                    .mapNotNull { KeyInfo.from(reader) }.toList()

            return AccountInfo(username, alias, fullname, isLocalPassword, keys)
        }
    }
}

@Parcelize
data class KeyInfo(val keyId:Int, val appname:String?, val lastUse: Date?): Parcelable {

    companion object {

        @JvmStatic
        fun from(reader: XmlPullParser): KeyInfo? {
            assert(reader.eventType==XmlPullParser.START_TAG && reader.name=="key")
            val keyId = reader.getAttributeValue(null, "id")?.toIntOrNull()
            val appname = reader.getAttributeValue(null, "appname")
            val lastUse = reader.getAttributeValue(null, "lastUse")?.toLongOrNull()?.let { Date(it) }

            assert(reader.nextTag()==XmlPullParser.END_TAG && reader.name=="key")
            return keyId?.let { KeyInfo(it, appname, lastUse) }
        }
    }
}
