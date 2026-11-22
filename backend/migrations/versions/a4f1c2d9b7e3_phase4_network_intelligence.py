"""phase 4 network intelligence

Revision ID: a4f1c2d9b7e3
Revises: 6384d2549255
Create Date: 2026-11-22 09:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a4f1c2d9b7e3'
down_revision = '6384d2549255'
branch_labels = None
depends_on = None

_CAPTURE_FK = lambda: sa.ForeignKeyConstraint(['capture_id'], ['captures.id'], ondelete='CASCADE')  # noqa: E731


def upgrade():
    with op.batch_alter_table('packets', schema=None) as batch_op:
        batch_op.add_column(sa.Column('tcp_window', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('tcp_window_scale', sa.SmallInteger(), nullable=True))

    op.create_table('advanced_analyses',
    sa.Column('capture_id', sa.Uuid(), nullable=False),
    sa.Column('schema_version', sa.Integer(), nullable=False),
    sa.Column('document', sa.JSON(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    _CAPTURE_FK(),
    sa.PrimaryKeyConstraint('capture_id')
    )

    op.create_table('tcp_connections',
    sa.Column('capture_id', sa.Uuid(), nullable=False),
    sa.Column('connection_id', sa.Integer(), autoincrement=False, nullable=False),
    sa.Column('flow_id', sa.Integer(), nullable=False),
    sa.Column('ip_version', sa.SmallInteger(), nullable=True),
    sa.Column('endpoint_a_ip', sa.String(length=45), nullable=False),
    sa.Column('endpoint_a_port', sa.Integer(), nullable=True),
    sa.Column('endpoint_b_ip', sa.String(length=45), nullable=False),
    sa.Column('endpoint_b_port', sa.Integer(), nullable=True),
    sa.Column('initiator_known', sa.Boolean(), nullable=False),
    sa.Column('state', sa.String(length=16), nullable=False),
    sa.Column('incomplete_reason', sa.String(length=16), nullable=True),
    sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
    sa.Column('first_packet', sa.Integer(), nullable=False),
    sa.Column('last_packet', sa.Integer(), nullable=False),
    sa.Column('duration_seconds', sa.Float(), nullable=False),
    sa.Column('syn_packet', sa.Integer(), nullable=True),
    sa.Column('syn_retransmissions', sa.Integer(), nullable=False),
    sa.Column('syn_to_synack_ms', sa.Float(), nullable=True),
    sa.Column('synack_to_ack_ms', sa.Float(), nullable=True),
    sa.Column('handshake_ms', sa.Float(), nullable=True),
    sa.Column('termination', sa.String(length=16), nullable=False),
    sa.Column('terminated_by', sa.String(length=4), nullable=True),
    sa.Column('capture_truncated', sa.Boolean(), nullable=False),
    sa.Column('truncation_reasons', sa.JSON(), nullable=False),
    sa.Column('packets', sa.Integer(), nullable=False),
    sa.Column('bytes', sa.BigInteger(), nullable=False),
    sa.Column('packets_a_to_b', sa.Integer(), nullable=False),
    sa.Column('packets_b_to_a', sa.Integer(), nullable=False),
    sa.Column('bytes_a_to_b', sa.BigInteger(), nullable=False),
    sa.Column('bytes_b_to_a', sa.BigInteger(), nullable=False),
    sa.Column('rst_packets', sa.Integer(), nullable=False),
    sa.Column('rst_from_a', sa.Integer(), nullable=False),
    sa.Column('rst_from_b', sa.Integer(), nullable=False),
    sa.Column('rst_evidence', sa.JSON(), nullable=False),
    sa.Column('retransmissions', sa.Integer(), nullable=False),
    sa.Column('duplicate_acks', sa.Integer(), nullable=False),
    sa.Column('zero_window_events', sa.Integer(), nullable=False),
    sa.Column('window_scaling', sa.String(length=40), nullable=False),
    sa.Column('window', sa.JSON(), nullable=False),
    _CAPTURE_FK(),
    sa.PrimaryKeyConstraint('capture_id', 'connection_id')
    )
    op.create_index('ix_tcpconn_capture_state', 'tcp_connections', ['capture_id', 'state'], unique=False)
    op.create_index('ix_tcpconn_capture_duration', 'tcp_connections', ['capture_id', 'duration_seconds'], unique=False)
    op.create_index('ix_tcpconn_capture_zerowin', 'tcp_connections', ['capture_id', 'zero_window_events'], unique=False)
    op.create_index('ix_tcpconn_capture_flow', 'tcp_connections', ['capture_id', 'flow_id'], unique=False)

    op.create_table('tcp_indicators',
    sa.Column('capture_id', sa.Uuid(), nullable=False),
    sa.Column('indicator_id', sa.Integer(), autoincrement=False, nullable=False),
    sa.Column('connection_id', sa.Integer(), nullable=False),
    sa.Column('flow_id', sa.Integer(), nullable=False),
    sa.Column('endpoint_a', sa.String(length=60), nullable=False),
    sa.Column('endpoint_b', sa.String(length=60), nullable=False),
    sa.Column('type', sa.String(length=24), nullable=False),
    sa.Column('side', sa.String(length=1), nullable=False),
    sa.Column('count', sa.Integer(), nullable=False),
    sa.Column('first_packet', sa.Integer(), nullable=True),
    sa.Column('last_packet', sa.Integer(), nullable=True),
    sa.Column('severity', sa.String(length=8), nullable=False),
    sa.Column('severity_rank', sa.SmallInteger(), nullable=False),
    sa.Column('confidence', sa.String(length=8), nullable=False),
    sa.Column('evidence', sa.JSON(), nullable=False),
    sa.Column('detail', sa.JSON(), nullable=False),
    _CAPTURE_FK(),
    sa.PrimaryKeyConstraint('capture_id', 'indicator_id')
    )
    op.create_index('ix_tcpind_capture_type', 'tcp_indicators', ['capture_id', 'type'], unique=False)
    op.create_index('ix_tcpind_capture_severity', 'tcp_indicators', ['capture_id', 'severity_rank'], unique=False)
    op.create_index('ix_tcpind_capture_conn', 'tcp_indicators', ['capture_id', 'connection_id'], unique=False)

    op.create_table('dns_transactions',
    sa.Column('capture_id', sa.Uuid(), nullable=False),
    sa.Column('transaction_id', sa.Integer(), autoincrement=False, nullable=False),
    sa.Column('transport', sa.String(length=3), nullable=False),
    sa.Column('client_ip', sa.String(length=45), nullable=False),
    sa.Column('client_port', sa.Integer(), nullable=True),
    sa.Column('server_ip', sa.String(length=45), nullable=False),
    sa.Column('server_port', sa.Integer(), nullable=True),
    sa.Column('dns_id', sa.Integer(), nullable=False),
    sa.Column('qname', sa.String(length=255), nullable=True),
    sa.Column('qtype', sa.String(length=12), nullable=True),
    sa.Column('question_count', sa.Integer(), nullable=False),
    sa.Column('questions', sa.JSON(), nullable=False),
    sa.Column('query_packet', sa.Integer(), nullable=True),
    sa.Column('response_packet', sa.Integer(), nullable=True),
    sa.Column('query_time', sa.DateTime(timezone=True), nullable=True),
    sa.Column('response_time', sa.DateTime(timezone=True), nullable=True),
    sa.Column('query_count', sa.Integer(), nullable=False),
    sa.Column('latency_ms', sa.Float(), nullable=True),
    sa.Column('latency_from_last_query_ms', sa.Float(), nullable=True),
    sa.Column('rcode', sa.Integer(), nullable=True),
    sa.Column('rcode_name', sa.String(length=12), nullable=True),
    sa.Column('truncated', sa.Boolean(), nullable=False),
    sa.Column('answer_count', sa.Integer(), nullable=True),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('note', sa.String(length=120), nullable=True),
    _CAPTURE_FK(),
    sa.PrimaryKeyConstraint('capture_id', 'transaction_id')
    )
    op.create_index('ix_dns_capture_latency', 'dns_transactions', ['capture_id', 'latency_ms'], unique=False)
    op.create_index('ix_dns_capture_status', 'dns_transactions', ['capture_id', 'status'], unique=False)
    op.create_index('ix_dns_capture_rcode', 'dns_transactions', ['capture_id', 'rcode'], unique=False)
    op.create_index('ix_dns_capture_server', 'dns_transactions', ['capture_id', 'server_ip'], unique=False)
    op.create_index('ix_dns_capture_client', 'dns_transactions', ['capture_id', 'client_ip'], unique=False)

    op.create_table('ip_traffic',
    sa.Column('capture_id', sa.Uuid(), nullable=False),
    sa.Column('ip', sa.String(length=45), nullable=False),
    sa.Column('ip_version', sa.SmallInteger(), nullable=True),
    sa.Column('sent_packets', sa.Integer(), nullable=False),
    sa.Column('sent_bytes', sa.BigInteger(), nullable=False),
    sa.Column('received_packets', sa.Integer(), nullable=False),
    sa.Column('received_bytes', sa.BigInteger(), nullable=False),
    _CAPTURE_FK(),
    sa.PrimaryKeyConstraint('capture_id', 'ip')
    )
    op.create_index('ix_iptraffic_capture_sent', 'ip_traffic', ['capture_id', 'sent_bytes'], unique=False)
    op.create_index('ix_iptraffic_capture_recv', 'ip_traffic', ['capture_id', 'received_bytes'], unique=False)

    op.create_table('ip_pairs',
    sa.Column('capture_id', sa.Uuid(), nullable=False),
    sa.Column('source_ip', sa.String(length=45), nullable=False),
    sa.Column('destination_ip', sa.String(length=45), nullable=False),
    sa.Column('packets', sa.Integer(), nullable=False),
    sa.Column('bytes', sa.BigInteger(), nullable=False),
    _CAPTURE_FK(),
    sa.PrimaryKeyConstraint('capture_id', 'source_ip', 'destination_ip')
    )

    op.create_table('anomaly_findings',
    sa.Column('capture_id', sa.Uuid(), nullable=False),
    sa.Column('finding_id', sa.Integer(), autoincrement=False, nullable=False),
    sa.Column('rule', sa.String(length=40), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('severity', sa.String(length=8), nullable=False),
    sa.Column('severity_rank', sa.SmallInteger(), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('reason', sa.Text(), nullable=False),
    sa.Column('evidence', sa.JSON(), nullable=False),
    sa.Column('affected_ips', sa.JSON(), nullable=False),
    sa.Column('affected_flows', sa.JSON(), nullable=False),
    sa.Column('packet_refs', sa.JSON(), nullable=False),
    sa.Column('thresholds', sa.JSON(), nullable=False),
    sa.Column('note', sa.String(length=200), nullable=False),
    _CAPTURE_FK(),
    sa.PrimaryKeyConstraint('capture_id', 'finding_id')
    )
    op.create_index('ix_anomaly_capture_severity', 'anomaly_findings', ['capture_id', 'severity_rank'], unique=False)
    op.create_index('ix_anomaly_capture_rule', 'anomaly_findings', ['capture_id', 'rule'], unique=False)


def downgrade():
    op.drop_table('anomaly_findings')
    op.drop_table('ip_pairs')
    op.drop_table('ip_traffic')
    op.drop_table('dns_transactions')
    op.drop_table('tcp_indicators')
    op.drop_table('tcp_connections')
    op.drop_table('advanced_analyses')
    with op.batch_alter_table('packets', schema=None) as batch_op:
        batch_op.drop_column('tcp_window_scale')
        batch_op.drop_column('tcp_window')
