package uk.ac.bournemouth.darwin.auth

import android.accounts.Account
import android.arch.lifecycle.LiveData
import android.arch.lifecycle.Observer
import android.arch.lifecycle.ViewModelProviders
import android.databinding.DataBindingUtil
import android.os.Bundle
import android.support.v4.app.Fragment
import android.support.v7.recyclerview.extensions.ListAdapter
import android.support.v7.util.DiffUtil
import android.support.v7.widget.RecyclerView
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import nl.adaptivity.android.coroutines.CompatCoroutineFragment
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
class AccountDetailFragment : CompatCoroutineFragment() {

    /**
     * The dummy content this fragment is presenting.
     */
    private var account: Account? = null
    private lateinit var binding: AccountDetailBinding
    private lateinit var accountInfo: LiveData<AccountInfo>

    private val keyAdapter = KeyAdapter()

    @Suppress("ClassName")
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
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        binding = DataBindingUtil.inflate(inflater, R.layout.account_detail, container, false)

        binding.keyList.adapter=keyAdapter

        val viewModel = ViewModelProviders.of(this).get(AccountsViewModel::class.java)
        // Show the dummy content as text in a TextView.
        account?.let { account ->
            binding.accountDetail.text = container!!.resources.getString(R.string.lbl_account_name, account.name)


            accountInfo = viewModel.getAccountInfo(account).invoke(this)

            accountInfo.observe(this, Observer<AccountInfo> { info ->
                binding.info = info
                keyAdapter.submitList(info?.keys?: emptyList())
            } )

        }
        viewModel.loading.observe(this) { binding.loading = it?: false }

        binding.refreshLayout.setOnRefreshListener {
            val a = account
            if (a!=null) {
                viewModel.getAccountInfo(a, true).invoke(this)
            }
        }


        return binding.root
    }


    companion object {
        /**
         * The fragment argument representing the item ID that this fragment
         * represents.
         */
        const val ARG_ACCOUNT = "account"
    }
}

private fun getInfoUrl(authBaseUrl: String?): URI {
    return URI.create("${if (authBaseUrl.isNullOrEmpty()) DarwinAuthenticator.DEFAULT_AUTH_BASE_URL else authBaseUrl}myaccount")
}


internal fun getAccountInfoHelper(authBaseUrl: String?, token: String?): AccountInfo? {
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
                return AccountInfo.from(reader, authBaseUrl)
            }
        } else {
            return null
        }
    } finally {
        conn.disconnect()
    }
}