package uk.ac.bournemouth.darwin.auth

import android.accounts.Account
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.support.v4.app.NavUtils
import android.support.v7.app.AppCompatActivity
import android.view.MenuItem

/**
 * An activity representing a single Account detail screen. This
 * activity is only used on narrow width devices. On tablet-size devices,
 * item details are presented side-by-side with a list of items
 * in a [AccountListActivity].
 */
class AccountDetailActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_account_detail)

        actionBar?.setDisplayHomeAsUpEnabled(true)
        // Show the Up button in the action bar, but only if there is an account list.

        // savedInstanceState is non-null when there is fragment state
        // saved from previous configurations of this activity
        // (e.g. when rotating the screen from portrait to landscape).
        // In this case, the fragment will automatically be re-added
        // to its container so we don't need to manually add it.
        // For more information, see the Fragments API guide at:
        //
        // http://developer.android.com/guide/components/fragments.html
        //
        if (savedInstanceState == null) {
            // Create the detail fragment and add it to the activity
            // using a fragment transaction.
            val fragment = AccountDetailFragment().apply {
                arguments = Bundle().apply {
                    putParcelable(AccountDetailFragment.ARG_ACCOUNT,
                            intent.getParcelableExtra<Account>(AccountDetailFragment.ARG_ACCOUNT))
                }
            }

            supportFragmentManager.beginTransaction()
                    .add(R.id.account_detail_container, fragment)
                    .commit()
        }
    }

    override fun onOptionsItemSelected(item: MenuItem) =
            when (item.itemId) {
                android.R.id.home -> {
                    // This ID represents the Home or Up button. In the case of this
                    // activity, the Up button is shown. Use NavUtils to allow users
                    // to navigate up one level in the application structure. For
                    // more details, see the Navigation pattern on Android Design:
                    //
                    // http://developer.android.com/design/patterns/navigation.html#up-vs-back

                    NavUtils.navigateUpTo(this, Intent(this, AccountListActivity::class.java))
                    true
                }
                else -> super.onOptionsItemSelected(item)
            }
}

fun Context?.accountDetailIntent(account: Account): Intent {
    return Intent(this, AccountDetailActivity::class.java).apply {
        putExtra(AccountDetailFragment.ARG_ACCOUNT, account)
    }
}
