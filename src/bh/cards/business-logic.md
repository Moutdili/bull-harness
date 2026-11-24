## Business logic
When: basket, checkout, payment, coupon, wallet, transfer, subscription routes; price or quantity fields.
Do:
1. Walk the normal flow once as user-a and write the steps down (`bh-note fact`).
2. Change one thing at a time on user-a's own objects: negative or huge quantity, price or currency in the request,
   coupon applied twice, a step skipped or replayed, an object of user-b inserted into user-a's flow.
3. Compare the state before and after (totals, balances, order status) and keep both responses.
Never: complete a real payment or order that costs the program money, touch real customers' objects.
