* completion api
    * input is a string
    * output is a string
* harness
    * formats the conversation as a conversation template
    * parses the return as a conversation object.
    * extracts the tool calls
    * extracts the messages to the user.
* tool environment
    * executes the extracted tool calls
* UI
    * takes messages from the user and passes to the harness
    * takes messages from the harness and passes to the user.

kinds of messages:
1) User messages to the assistant.
2) Assistant messages to the user.
3) User tool calls
4) Assistant tool calls
5) Assistant thoughts

Three actors:
  * User
  * Assistant
  * REPL

* Messages for REPL start with `!`
* Messages that are comments start with `#`
* Messages for the user or the assistant don't start with `!`, `#`, or `@`

Should the REPL be bash or JS or Python or something else?

I think we can combine the UI with the harness,
but the inference API and the tool call env should be remote.

Tool calls need real sandboxing even if run locally.



