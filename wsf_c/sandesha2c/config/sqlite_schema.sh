#!/bin/bash
sqlite3 sandesha2_db "drop table if exists create_seq;"
sqlite3 sandesha2_db "drop table if exists invoker;"
sqlite3 sandesha2_db "drop table if exists sender"
sqlite3 sandesha2_db "drop table if exists next_msg"
sqlite3 sandesha2_db "drop table if exists seq_property"
sqlite3 sandesha2_db "drop table if exists msg"
sqlite3 sandesha2_db "drop table if exists response"
sqlite3 sandesha2_db "create table create_seq(create_seq_msg_id varchar(100) primary key, 
    internal_seq_id varchar(200), seq_id varchar(200), create_seq_msg_store_key varchar(100),
    ref_msg_store_key varchar(100))"
sqlite3 sandesha2_db "create table invoker(msg_ctx_ref_key varchar(100) primary key, 
    msg_no long, seq_id varchar(200), is_invoked boolean)"
sqlite3 sandesha2_db "create table sender(msg_id varchar(100) primary key, 
    msg_ctx_ref_key varchar(100), internal_seq_id varchar(200), sent_count int, 
    msg_no long, send boolean, resend boolean, time_to_send long, msg_type int, 
    seq_id varchar(200), wsrm_anon_uri varchar(100), to_address varchar(100))"
sqlite3 sandesha2_db "create table seq_property(id varchar(200) , 
    seq_id varchar(200), name varchar(200), value varchar(200))"
