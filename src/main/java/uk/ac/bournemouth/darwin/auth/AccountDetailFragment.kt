package uk.ac.bournemouth.darwin.auth

import android.accounts.Account
import android.accounts.AccountManager
import android.arch.lifecycle.MutableLiveData
import android.arch.lifecycle.Observer
import android.databinding.DataBindingUtil
import android.os.Bundle
import android.support.v4.app.Fragment
import android.support.v7.recyclerview.extensions.ListAdapter
import android.support.v7.util.DiffUtil
import android.support.v7.widget.RecyclerView
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import kotlinx.coroutines.experimental.launch
import nl.adaptivity.android.coroutines.getAuthToken
import org.xmlpull.v1.XmlPullParserFactory
import uk.ac.bournemouth.darwin.auth.databinding.AccountDetailBinding
import uk.ac.bournemouth.darwin.auth.databinding.KeyListContentBinding
import java.net.HttpURLConnection
import java.net.URI

/**
 * A fragment representing a single Account detail screen.
 * This fragment is either contained in a [AccountListActivity]
 * in two-pane mode (on tablets) or a [AccountDetailActivity]
 * on handsets.
 */
class AccountDetailFragment : Fragment() {

    /**
     * The dummy content this fragment is presenting.
     */
    private var account: Account? = null
    private lateinit var binding: AccountDetailBinding
    private var accountInfo= MutableLiveData<AccountInfo>()
    var infoPending: Boolean = false

    private val keyAdapter = KeyAdapter()

    object KEYINFO_DIFF_CALLBACK: DiffUtil.ItemCallback<KeyInfo>() {
        override fun areItemsTheSame(oldItem: KeyInfo, newItem: KeyInfo): Boolean {
            return oldItem.keyId == newItem.keyId
        }

        override fun areContentsTheSame(oldItem: KeyInfo, newItem: KeyInfo): Boolean {
            return oldItem == newItem
        }
    }

    class KeyAdapter(data: List<KeyInfo> = emptyList()): ListAdapter<KeyInfo, KeyViewHolder>(KEYINFO_DIFF_CALLBACK) {
        init {
            setHasStableIds(true)
            if (data.isNotEmpty()) submitList(data)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): KeyViewHolder {
            return KeyViewHolder(DataBindingUtil.inflate(LayoutInflater.from(parent.context), R.layout.key_list_content, parent, false))
        }

        override fun onBindViewHolder(holder: KeyViewHolder, position: Int) {
            holder.binding.keyInfo = getItem(position)
        }

        override fun getItemId(position: Int): Long {
            return getItem(position).keyId.toLong()
        }

    }

    class KeyViewHolder(val binding: KeyListContentBinding): RecyclerView.ViewHolder(binding.root)


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        arguments?.let {
            if (it.containsKey(ARG_ACCOUNT)) {
                account = it.getParcelable(ARG_ACCOUNT)
            }
        }
        savedInstanceState?.apply { infoPending = getBoolean(ARG_INFO_PENDING, false) }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean(ARG_INFO_PENDING, infoPending)
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        binding = DataBindingUtil.inflate(inflater, R.layout.account_detail, container, false)
        binding.keyList.adapter=keyAdapter

        // Show the dummy content as text in a TextView.
        account?.let { account ->
            binding.accountDetail.text = "Account: ${account.name}"

            val authBaseUrl = getAuthBase(AccountManager.get(activity), account)

            if (! infoPending) {
                requestAccountInfo(authBaseUrl, account)
                infoPending = true
            }


            accountInfo.observe(this, Observer<AccountInfo> { info ->
                binding.info = info
                keyAdapter.submitList(info?.keys?: emptyList())
            } )

        }


        return binding.root
    }

    private fun requestAccountInfo(authBaseUrl: String?, account: Account) {
        launch {
            val am = AccountManager.get(activity!!)
            val token = am.getAuthToken(activity!!, account, DWN_ACCOUNT_TOKEN_TYPE)
            Log.d("AccountDetailFragment", "authtoken: $token")

            val info = getAccountInfoHelper(authBaseUrl, token)

            if (info != null) {
                updateInfo(info)
            } else {
                am.invalidateAuthToken(DWN_ACCOUNT_TYPE, token)
                getAccountInfoHelper(authBaseUrl, token)?.let { updateInfo(it) }
            }
        }
    }

    private fun updateInfo(accountInfo: AccountInfo) {
        activity?.runOnUiThread {
            this.accountInfo.value = accountInfo
            infoPending = false
        }
    }


    companion object {
        /**
         * The fragment argument representing the item ID that this fragment
         * represents.
         */
        const val ARG_ACCOUNT = "account"
        const val ARG_INFO_PENDING = "infoPending"
    }
}

private fun getInfoUrl(authBaseUrl: String?): URI {
    return URI.create("${if (authBaseUrl.isNullOrEmpty()) DarwinAuthenticator.DEFAULT_AUTH_BASE_URL else authBaseUrl}myaccount")
}


private fun getAccountInfoHelper(authBaseUrl: String?, token: String?): AccountInfo? {
    val conn = getInfoUrl(authBaseUrl).toURL().openConnection() as HttpURLConnection
    try {
        conn.addRequestProperty("DWNID", token)
        conn.addRequestProperty("Accept-Content", "text/xml")
        val response = conn.responseCode
        if (response < 400) {
            conn.inputStream.use {
                val reader = XmlPullParserFactory.newInstance().newPullParser()
                        .apply { setInput(it, conn.getHeaderField("Content-Encoding") ?: "UTF8") }

                reader.nextTag()
                return AccountInfo.from(reader)
            }
        } else {
            return null
        }
    } finally {
        conn.disconnect()
    }
}