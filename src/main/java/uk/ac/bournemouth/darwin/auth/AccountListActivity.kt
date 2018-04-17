package uk.ac.bournemouth.darwin.auth

import android.accounts.Account
import android.accounts.AccountManager
import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import android.support.v7.widget.RecyclerView
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import kotlinx.android.synthetic.main.account_list_content.view.*
import kotlinx.android.synthetic.main.activity_account_list.*

/**
 * An activity representing a list of Pings. This activity
 * has different presentations for handset and tablet-size devices. On
 * handsets, the activity presents a list of items, which when touched,
 * lead to a [AccountDetailActivity] representing
 * item details. On tablets, the activity presents the list of items and
 * item details side-by-side using two vertical panes.
 */
class AccountListActivity : AppCompatActivity() {

    /**
     * Whether or not the activity is in two-pane mode, i.e. running on a tablet
     * device.
     */
    private var twoPane: Boolean = false
    private lateinit var adapter: AccountRecyclerViewAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_account_list)

        if (account_detail_container != null) {
            // The detail container view will be present only in the
            // large-screen layouts (res/values-w900dp).
            // If this view is present, then the
            // activity should be in two-pane mode.
            twoPane = true
        }

        val accounts = AccountManager.get(this).getAccountsByType(DWN_ACCOUNT_TYPE).toList()
        if (accounts.size==1) {
            startActivity(accountDetailIntent(accounts[0]))
            finish()
        } else {
            adapter = AccountRecyclerViewAdapter(this, accounts, twoPane)
            account_list.adapter = adapter
        }
    }

    class AccountRecyclerViewAdapter(private val parentActivity: AccountListActivity,
                                     private val values: List<Account>,
                                     private val twoPane: Boolean) :
            RecyclerView.Adapter<AccountRecyclerViewAdapter.ViewHolder>() {

        private val onClickListener: View.OnClickListener

        init {
            val hasOthers = values.size>1

            onClickListener = View.OnClickListener { v ->
                val account = v.tag as Account
                if (twoPane) {
                    val fragment = AccountDetailFragment().apply {
                        arguments = Bundle().apply {
                            putParcelable(AccountDetailFragment.ARG_ACCOUNT, account)
                        }
                    }
                    parentActivity.supportFragmentManager
                            .beginTransaction()
                            .replace(R.id.account_detail_container, fragment)
                            .commit()
                } else {
                    val context = v.context
                    val intent = context.accountDetailIntent(account)
                    v.context.startActivity(intent)
                }
            }
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
            val view = LayoutInflater.from(parent.context)
                    .inflate(R.layout.account_list_content, parent, false)
            return ViewHolder(view)
        }

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            val account = values[position]
            holder.idView.text = account.name
            holder.contentView.text = account.type

            with(holder.itemView) {
                tag = account
                setOnClickListener(onClickListener)
            }
        }

        override fun getItemCount() = values.size

        inner class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
            val idView: TextView = view.id_text
            val contentView: TextView = view.content
        }
    }
}
